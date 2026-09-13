#!/usr/bin/env python3
"""
Velociraptor responder router.
Reads from job directory (sys.argv[1]) when available, stdin otherwise.
"""
import json
import sys
import os

# Read input -- job directory takes priority over stdin
job_dir = sys.argv[1] if len(sys.argv) > 1 else None
if job_dir and os.path.isfile(f"{job_dir}/input/input.json"):
    with open(f"{job_dir}/input/input.json") as f:
        raw = json.load(f)
else:
    raw = json.load(sys.stdin)

observable_datatype = raw.get("data", {}).get("dataType", "")

if observable_datatype == "process-path":
    sys.path.insert(0, '/opt/cortex/Cortex-Analyzers/responders/Velociraptor')
    from vr_killprocess import VRKillProcess
    VRKillProcess().run()

elif observable_datatype == "ip":
    sys.path.insert(0, '/opt/cortex/Cortex-Analyzers/responders/Velociraptor')
    from vr_blockip import VRBlockIP
    VRBlockIP().run()

else:
    # Original base Velociraptor behavior -- pass job_dir via argv
    import grpc, yaml, base64, re
    from cortexutils.responder import Responder
    from pyvelociraptor import api_pb2, api_pb2_grpc

    class VelociraptorBase(Responder):
        def __init__(self):
            Responder.__init__(self)
            self.configpath = self.get_param('config.velociraptor_client_config', None)
            self.config_content_base64 = self.get_param('config.velociraptor_client_config_content_base64', None)
            if not self.configpath and not self.config_content_base64:
                self.error("Either velociraptor_client_config or velociraptor_client_config_content_base64 must be provided!")
            if self.config_content_base64:
                decoded = base64.b64decode(self.config_content_base64).decode('utf-8')
                self.config = yaml.load(decoded, Loader=yaml.FullLoader)
            else:
                self.config = yaml.load(open(self.configpath).read(), Loader=yaml.FullLoader)
            self.artifact = self.get_param('config.velociraptor_artifact', None, 'Artifact missing!')
            self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
            self.observable = self.get_param('data.data', None, 'Data missing!')
            self.max_wait = self.get_param('config.query_max_duration', 600)

        def run(self):
            Responder.run(self)
            case_id = self.get_param('data._parent')
            creds = grpc.ssl_channel_credentials(
                root_certificates=self.config["ca_certificate"].encode("utf8"),
                private_key=self.config["client_private_key"].encode("utf8"),
                certificate_chain=self.config["client_cert"].encode("utf8"))
            options = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
            with grpc.secure_channel(self.config["api_connection_string"], creds, options) as channel:
                stub = api_pb2_grpc.APIStub(channel)
                if self.observable_type == "ip":
                    client_query = "select client_id from clients() where last_ip =~ '"+ self.observable +"'"
                elif re.search(r'fqdn|other', self.observable_type):
                    client_query = "select client_id from clients(search='host:" + self.observable + "')"
                else:
                    self.report({'message': "Not a valid data type!"})
                    return
                client_id = None
                client_request = api_pb2.VQLCollectorArgs(max_wait=60,
                    Query=[api_pb2.VQLRequest(Name="TheHive-ClientQuery", VQL=client_query)])
                for client_response in stub.Query(client_request):
                    try:
                        client_results = json.loads(client_response.Response)
                        client_id = client_results[0]['client_id']
                    except: pass
                artifact_query = "LET collection <= collect_client(client_id='"+ client_id +"',artifacts=['" + self.artifact + "'], spec=dict()) LET collection_completed <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1 SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id, artifact=collection_completed.Flow.artifacts_with_results[0])"
                request = api_pb2.VQLCollectorArgs(max_wait=self.max_wait,
                    Query=[api_pb2.VQLRequest(Name="TheHive-Query", VQL=artifact_query)])
                for response in stub.Query(request):
                    try:
                        self.report({'message': json.loads(response.Response)})
                    except: pass

        def operations(self, raw):
            return [self.build_operation('AddTagToArtifact', tag='velociraptor')]

    VelociraptorBase().run()
