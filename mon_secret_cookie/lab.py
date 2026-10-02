"""Serveur pédagogique lié exclusivement à 127.0.0.1."""
def create_app():
    from flask import Flask, request, make_response, redirect
    app=Flask(__name__)
    @app.before_request
    def protect_host():
        if request.host.split(':')[0] not in ('localhost','127.0.0.1'):
            return 'Hôte refusé',400
    @app.get('/')
    def index():
        present='présent' if request.cookies.get('msc_lab') else 'absent'
        return f"<h1>Cookie Lab local</h1><p>Cookie fictif : {present}. Aucune valeur affichée.</p><form method='post' action='/set'><button>Créer un cookie HttpOnly / SameSite=Strict</button></form><form method='post' action='/clear'><button>Effacer</button></form><p>HTTP local : Secure désactivé. En HTTPS réel, activez Secure.</p>"
    @app.post('/set')
    def set_cookie():
        response=make_response(redirect('/'))
        response.set_cookie('msc_lab','FICTIF',httponly=True,samesite='Strict',secure=False,max_age=600)
        return response
    @app.post('/clear')
    def clear():
        response=make_response(redirect('/'))
        response.delete_cookie('msc_lab')
        return response
    return app

def serve(port):
    create_app().run(host='127.0.0.1',port=port,debug=False,use_reloader=False)
