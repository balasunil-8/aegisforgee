from pentestlab_api import app
import json

with app.test_client() as c:
    resp = c.post('/api/ai/detect', json={'text': "admin' OR '1'='1 --"})
    print('Status', resp.status_code)
    print(json.dumps(resp.get_json(), indent=2))
