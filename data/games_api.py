import flask
from flask import jsonify, make_response, request

from data import db_session
from data.games import Games


blueprint = flask.Blueprint(
    'games_api',
    __name__,
    template_folder='templates'
)


# Я не стал ставить защиту, чтобы api можно было проверить
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


@blueprint.route('/api/games', methods=['POST'])
def create_games():
    if not request.json:
        return make_response(jsonify({'error': 'Empty request'}), 400)
    elif not all(key in request.json for key in
                 ['name', 'author', 'tags', 'description', 'full_desc', 'price',
                  'sale', 'sale_price', 'img', 'release_date']):
        return make_response(jsonify({'error': 'Bad request'}), 400)
    db_sess = db_session.create_session()
    games = Games(
        name=request.json['name'],
        author=request.json['author'],
        tags=request.json['tags'],
        description=request.json['description'],
        full_desc=request.json['full_desc'],
        price=request.json['price'],
        sale=request.json['full_desc'],
        sale_price=request.json['sale_price'],
        img=request.json['img'],
        release_date=request.json['release_date']
    )
    db_sess.add(games)
    db_sess.commit()
    return jsonify({'id': games.id})


@blueprint.route('/api/games/<int:games_id>', methods=['DELETE'])
def delete_games(games_id):
    db_sess = db_session.create_session()
    games = db_sess.query(Games).get(games_id)
    if not games:
        return make_response(jsonify({'error': 'Not found'}), 404)
    db_sess.delete(games)
    db_sess.commit()
    return jsonify({'success': 'OK'})


@blueprint.route('/api/games/<int:games_id>', methods=['POST'])
def edit_games():
    if not request.json:
        return make_response(jsonify({'error': 'Empty request'}), 400)
    elif not all(key in request.json for key in
                 ['name', 'author', 'tags', 'description', 'full_desc', 'price',
                  'sale', 'sale_price', 'img', 'release_date']):
        return make_response(jsonify({'error': 'Bad request'}), 400)
    db_sess = db_session.create_session()
    games = Games(
        name=request.json['name'],
        author=request.json['author'],
        tags=request.json['tags'],
        description=request.json['description'],
        full_desc=request.json['full_desc'],
        price=request.json['price'],
        sale=request.json['full_desc'],
        sale_price=request.json['sale_price'],
        img=request.json['img'],
        release_date=request.json['release_date']
    )
    db_sess.add(games)
    db_sess.commit()
    return jsonify({'id': games.id})
