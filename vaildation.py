from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField
from wtforms.validators import DataRequired, Length

class AddForm(FlaskForm):
    part = StringField("Part Name", validators=
                        [DataRequired(), Length(min=2, max=20)])
    
    quantity = IntegerField("Quantity", validators=[DataRequired()])
    
    price = IntegerField("Price", validators=[DataRequired()])
