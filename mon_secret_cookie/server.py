"""API locale en lecture seule pour un client IA ou un tunnel SSH."""
import hmac
import os
from flask import Flask, jsonify, request
from . import core, security


def create_app(token=None):
    secret = token if token is not None else os.environ.get('MSC_API_TOKEN', '')
    if len(secret) < 32 or not secret.isascii() or any(c.isspace() for c in secret):
        raise core.AuditError('MSC_API_TOKEN : secret ASCII sans espaces, 32 caractères minimum requis.')
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=4096)

    @app.before_request
    def authenticate():
        supplied = request.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied.encode('utf-8'), ('Bearer ' + secret).encode('ascii')):
            return jsonify(error='Authentification requise.'), 401

    @app.after_request
    def protect(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.errorhandler(core.AuditError)
    def audit_error(error):
        return jsonify(error=str(error)), 400

    @app.get('/api/health')
    def health():
        return jsonify(status='ok', mode='read-only')

    @app.get('/api/cibles')
    def targets():
        return jsonify(cibles=security.targets())

    @app.get('/api/autorisations')
    def authorizations():
        return jsonify(security.authorizations())

    @app.get('/api/nouvelles')
    def new_assets():
        return jsonify(security.new_assets())

    @app.get('/api/rapports')
    def reports():
        return jsonify(security.reports())

    @app.get('/api/outils')
    def tools():
        missions = security.reports()['missions']
        latest = next((m for m in reversed(missions) if 'tools' in m), None)
        return jsonify(tools=latest['tools'] if latest else {},
                       observed_at=latest['started'] if latest else None,
                       note='Dernier diagnostic enregistré ; utilisez le CLI outils pour un diagnostic actuel.')

    return app


def serve(port):
    if not 1024 <= port <= 65535:
        raise core.AuditError('Port entre 1024 et 65535 requis.')
    create_app().run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
