from flask import Flask, jsonify, request
import ssl
import rethinkdb as r
import os

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('server.crt', 'server.key')

app = Flask(__name__)

global ENROLL_SECRET
ENROLL_SECRET = 'this_is_a_secret'
global FAILED_ENROLL_RESPONSE
FAILED_ENROLL_RESPONSE = {
    'node_invalid': True
}
global ENROLL_RESPONSE
ENROLL_RESPONSE = {
    'node_key': 'this_is_a_node_secret'
}
global NODE_KEYS
NODE_KEYS = [
    'this_is_a_node_secret',
    'this_is_also_a_node_secret',
]
global EXAMPLE_CONFIG
EXAMPLE_CONFIG = {
    "schedule": {
        "h": {"query": "select hostname from system_info;", "interval": 60},
    },
    "node_invalid": False,
}
global ENROLL_RESET
ENROLL_RESET = {
    "count": 1,
    "max": 3,
}
global EXAMPLE_DISTRIBUTED
EXAMPLE_DISTRIBUTED = {
    "queries": {
        "hostname": "select hostname from system_info;",
    }
}
# A 'node' variation of the TLS API uses a GET for config.
global EXAMPLE_NODE_CONFIG
EXAMPLE_NODE_CONFIG = EXAMPLE_CONFIG
EXAMPLE_NODE_CONFIG["node"] = True


class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


# ROUTES #
@app.before_request
def before_request():
    global conn
    conn = r.connect(db='osquery')
    global NODE_KEYS
    NODE_KEYS = r.db('osquery').table('nodes').get_field('node_key').run(conn)


@app.teardown_request
def teardown_request(exception):
    try:
        conn.close()
    except:
        pass


@app.route('/enroll', methods=['POST'])
def enroll():
    content = request.json
    host_identifier = content['host_identifier']
    if ENROLL_SECRET != content['enroll_secret']:
        return jsonify(FAILED_ENROLL_RESPONSE)
    else:
        existing_node = r.table('nodes').get(host_identifier).run(conn)
        if existing_node:
            node = {
                'id': host_identifier,
                'node_key': existing_node['node_key'],
                'enrolled_on': r.now(),
                'last_ip': request.remote_addr
            }
            r.table('nodes').insert(node, conflict='update').run(conn)
            return jsonify({'node_key': existing_node['node_key']})
        else:
            print 'Enrolling {}'.format(host_identifier)
            node_key = os.urandom(16).encode('hex')
            node = {
                'id': host_identifier,
                'node_key': node_key,
                'enrolled_on': r.now(),
                'last_ip': request.remote_addr
            }
            r.table('nodes').insert(node).run(conn)
            return jsonify({'node_key': node_key})


@app.route('/config', methods=['GET', 'POST'])
def config(node=False):
    content = request.json
    # return jsonify({})
    print content
    if 'node_key' not in content or content['node_key'] not in NODE_KEYS:
        return jsonify(FAILED_ENROLL_RESPONSE)

    # This endpoint will also invalidate the node secret key (node_key)
    # after several attempts to test re-enrollment.
    # ENROLL_RESET["count"] += 1
    # if ENROLL_RESET["count"] % ENROLL_RESET["max"] == 0:
    #     ENROLL_RESET["first"] = 0
    #     return jsonify(FAILED_ENROLL_RESPONSE)
    if request.method == 'GET':
        return jsonify(EXAMPLE_NODE_CONFIG)
    else:
        print EXAMPLE_CONFIG
        return jsonify(EXAMPLE_CONFIG)


@app.route('/distributed_read', methods=['POST'])
def distributed_read():
    content = request.json
    if 'node_key' not in content or content['node_key'] not in NODE_KEYS:
        return jsonify(FAILED_ENROLL_RESPONSE)
    distributed_queries = {}
    queries = r.table('queries').run(conn)
    for q in queries:
        distributed_queries.setdefault(q['name'], q['query'])
    response = {
        'queries': distributed_queries
    }
    return jsonify(response)


@app.route('/distributed_write', methods=['POST'])
def distributed_write():
    content = request.json
    print content
    return jsonify({})


@app.route('/log', methods=['POST'])
def log():
    content = request.json
    r.table('logs').insert(content).run(conn)
    if content['log_type'] == 'result':
        for d in content['data']:
            hostname = d['columns'].get('hostname', None)
            if hostname:
                print '{}: {}'.format(d['host_identifier'], hostname)
    return jsonify({})


@app.route('/queries')
def get_queries():
    cursor = r.table('queries').run(conn)
    return jsonify(list(cursor))


@app.route('/queries/<qname>')
def get_query(qname):
    cursor = r.table('queries').filter({'name': qname}).run(conn)
    response = next(cursor, None)
    if response:
        return jsonify(response)
    else:
        return jsonify({})


@app.route('/queries/<qname>', methods=['DELETE'])
def del_query(qname):
    cursor = r.table('queries').filter({'name': qname}).run(conn)
    response = next(cursor, None)
    if response:
        changes = r.table('queries').filter({'name': qname}).delete().run(conn)
        return jsonify(changes)
    else:
        raise InvalidUsage('Query with name "{}" not found'.format(qname),
                           status_code=404)

if __name__ == '__main__':
    app.run(ssl_context=context)
