#!/usr/bin/env python3
from cortexutils.responder import Responder

class VRKillProcess(Responder):
    def __init__(self):
        Responder.__init__(self)
        try:
            self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
            self.observable = self.get_param('data.data', None, 'Data missing!')
            self.case_id = self.get_param('data.case._id', None, 'Parent case id missing!')
            self.thehive_url = self.get_param('config.thehive_url', None, 'thehive_url missing!')
            self.thehive_apikey = self.get_param('config.thehive_apikey', None, 'thehive_apikey missing!')
            self.really_do_it = self.get_param('config.really_do_it', False)
            self.max_wait = self.get_param('config.query_max_duration', 600)
            self.configpath = self.get_param('config.velociraptor_client_config', None)
            self.config_content_base64 = self.get_param('config.velociraptor_client_config_content_base64', None)
        except Exception as e:
            self.report({'message': f'INIT EXCEPTION: {type(e).__name__}: {e}'})
            raise

    def run(self):
        Responder.run(self)
        self.report({
            'message': 'INIT OK - debug checkpoint',
            'observable_type': self.observable_type,
            'observable': self.observable,
            'case_id': self.case_id,
            'thehive_url': self.thehive_url,
            'really_do_it': self.really_do_it,
            'configpath': self.configpath,
        })

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='vr-debug')]

if __name__ == '__main__':
    VRKillProcess().run()
