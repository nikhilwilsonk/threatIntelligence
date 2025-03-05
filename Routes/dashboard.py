
from flask import Blueprint, jsonify, request,render_template
from services import OSINTCollector
from Models.ThreatIntelligenceModel import ThreatIntelligence

dashboard_bp = Blueprint('dashboard', __name__)
@dashboard_bp.route('/url-analysis', methods=['GET', 'POST'])
def url_analysis():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            collector = OSINTCollector()
            analysis_result = collector.analyze_url(url)
            
            return jsonify(analysis_result)
    return render_template('url_analysis.html')

    