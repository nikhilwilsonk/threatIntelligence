from mongoengine import Document, StringField, DateTimeField, ListField, FloatField
from datetime import datetime

class ThreatIntelligence(Document):
    source = StringField(required=True)
    threat_type = StringField(required=True)
    severity = FloatField(required=True)
    indicators = ListField(StringField())
    description = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'threat_intelligence',
        'indexes': [
            'source',
            'threat_type',
            '-timestamp'
        ]
    }