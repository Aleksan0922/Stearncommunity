import flask
from flask import jsonify, make_response, request

from data import db_session
from data.games import Games


blueprint = flask.Blueprint(
    'games_api',
    __name__,
    template_folder='templates'
)


@blueprint.route('/api/games')
def get_games():
    db_sess = db_session.create_session()
    games = db_sess.query(Games).all()
    return jsonify(
        {
            'games':
                [item.to_dict()
                 for item in games]
        }
    )


@blueprint.route('/api/games/<int:games_id>', methods=['GET'])
def get_one_games(games_id):
    db_sess = db_session.create_session()
    games = db_sess.query(Games).get(games_id)
    if not games:
        return make_response(jsonify({'error': 'Not found'}), 404)
    return jsonify(
        {
            'games': games.to_dict()
        }
    )