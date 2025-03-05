from flask import Flask,Blueprint,render_template,jsonify,request
from flask_pymongo import PyMongo
from flask_cors import CORS
import logging
from config import Config
from mongoengine import connect
from services import OSINTCollector

mongo = PyMongo()
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    connect(config_class.DATABASE_NAME, host=config_class.MONGODB_URI)

    dashboard_bp = Blueprint('dashboard', __name__)
    
    @dashboard_bp.route('/', methods=['GET'])
    def index():
        return render_template('url_analysis.html')
    
    @dashboard_bp.route('/api/url-analysis', methods=['POST'])
    def url_analysis():
        url = request.json.get('url') if request.is_json else request.form.get('url')
        if url:
            collector = OSINTCollector()
            analysis_result = collector.analyze_url(url)
            return jsonify(analysis_result)
        return jsonify({'error': 'No URL provided'}), 400

    app.register_blueprint(dashboard_bp)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)