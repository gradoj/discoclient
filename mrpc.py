import requests
import json

commands=('info_height','info_name','info_block_age','info_p2p_status','info_region','info_summary','info_location','info_version','peer_addr')

class mrpc:
    def __init__(self):
        self.session = requests.Session()
        self.host = 'http://miner:4467'
        self.header = {'Content-type': 'application/json'}
        self.payload = {"jsonrpc":"2.0",
                        "id":1,
                        "method":"",
                        "params":""}
    def get(self,cmd,params=[]):
        self.payload["method"]=cmd
        self.payload["params"]=params
        try:
            response=self.session.post(self.host, json=self.payload, headers=self.header).json()['result']
        except KeyError:
            response=self.session.post(self.host, json=self.payload, headers=self.header).json()
        return(response)

    def address(self):

        miner_addr = self.get('peer_addr')['peer_addr'].split('/p2p/')[1]
        return miner_addr

    def name(self):
        miner_name = self.get('info_name')['name']
        return miner_name

    def height(self):
        block_height = self.get('info_height')['height']
        return block_height


def test_all():
    m=mrpc()

    for cmd in commands:
        try:
            print(cmd+'\n',json.dumps(m.get(cmd), indent = 1))
            print('\n')
        except:
            print('error',cmd)
            continue


if __name__ == "__main__":
    m=mrpc()
    print(m.address())
    print(m.name())
    print(m.height())
    print(test_all())
