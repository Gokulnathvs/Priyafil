
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.subplots as sp
import csv
from werkzeug.utils import secure_filename
import sqlite3
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import logout_user
from flask_login import UserMixin, login_user, LoginManager, login_required
from flask_wtf import FlaskForm
from pyparsing import GoToColumn
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError,EqualTo
from flask_bcrypt import Bcrypt
import secrets
from flask import session
from flask import flash
import os



DATABASE1="instance/users.db"

def get_db_connection_user():
    connuser = sqlite3.connect(DATABASE1)
    connuser.row_factory = sqlite3.Row
    return connuser

app=Flask(__name__)
app.secret_key = "abc"
bcrypt = Bcrypt(app)
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "sqlite:///users.db"  # SQLite database file path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)





login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    reset_token = db.Column(db.String(100))

def generate_reset_token():
    reset_token = secrets.token_urlsafe(30)
    return reset_token

class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"},
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Password"},
    )

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"},
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Password"},
    )

    submit = SubmitField("Login")
    




    
@app.route('/')
def starter():
    return render_template('starter.html')

@app.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()

        if user:
            # Generate a reset token
            reset_token = generate_reset_token()

            # Update the user's reset token in the database
            user.reset_token = reset_token
            db.session.commit()

            # Send the reset token to the user via email or other means
            # Add your code here to send the reset token to the user

            flash('Reset token has been sent to your username.')  # Optional, for displaying a message to the user
            return redirect(url_for('resetpassword', reset_token=reset_token))

        flash('Invalid username.')  # Optional, for displaying a message to the user

    return render_template('forgotpass.html')

@app.route('/resetpassword/<reset_token>', methods=['GET', 'POST'])
def resetpassword(reset_token):
    user = User.query.filter_by(reset_token=reset_token).first()

    if not user:
        flash('Invalid or expired reset token.')  # Optional, for displaying a message to the user
        return redirect(url_for('forgotpass'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            # Update the user's password in the database
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            user.reset_token = None  # Reset the reset token
            db.session.commit()

            flash('Your password has been reset.')  # Optional, for displaying a message to the user
            return redirect(url_for('login'))

        flash('New password and confirm password do not match.')  # Optional, for displaying a message to the user

    return render_template('resetpassword.html', reset_token=reset_token,new_password=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session["username"] = user.username  
                return redirect(url_for("index3"))
        flash("Invalid username or password.")  # Display error message

    return render_template("login.html", form=form,user=True)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("username", None)  # Remove the username from the session
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            error_message = "Username already exists. Please choose a different username."
            flash(error_message, "error")
            return render_template("register.html", form=form,existing_user=True)

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html", form=form,existing_user=True)



app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/uploaddata')
def uploaddata():
    
    username = session.get("username")
    
    return render_template('uploaddata.html', username=username)


@app.route('/graphselection', methods=['POST'])
def graphselection():
    
    username = session.get("username")
    
    if 'file' not in request.files:
        return 'No file found'

    file = request.files['file']
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    df = pd.read_csv(file_path)
    column_names = df.columns.tolist()

    return render_template('graphselection.html', column_names=column_names, filename=filename, username=username)

@app.route('/plot', methods=['POST'])
def plot():
    
    username = session.get("username")
    
    graph_types = request.form.getlist('graph_type')  # Get multiple selected graph types

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], request.form['filename'])
    df = pd.read_csv(file_path)

    x_axis = request.form.get('x_axis')  # Get the selected X-axis column name
    y_axis = request.form.get('y_axis')  # Get the selected Y-axis column name

    if not x_axis or not y_axis:
        return 'Invalid column names selected'

    plot_filenames = []

    for graph_type in graph_types:
        if graph_type == 'bar':
            grouped_df = df.groupby(x_axis)[y_axis].sum().reset_index()

            fig = go.Figure([go.Bar(x=grouped_df[x_axis], y=grouped_df[y_axis])])
            fig.update_layout(               
                title="Bar chart",
                xaxis_title=x_axis,
                yaxis_title=f"Sum of {y_axis}",
                yaxis=dict(
                    tickformat=',.0f'  # Set tickformat to scientific notation with 2 decimal places
                )
            )
            fig.update_traces(marker_color='yellow', marker_line=dict(color='lightgreen', width=2))
            fig.update_layout(plot_bgcolor='rgba(0, 0, 0, 0)')

            fig.show()
            
        elif graph_type == 'line':           
                    
            grouped_df = df.groupby(x_axis)[y_axis].sum().reset_index()

            fig = go.Figure([go.Scatter(x=grouped_df[x_axis], y=grouped_df[y_axis], mode='lines')])
            fig.update_layout(
                title="Line chart",
                xaxis_title=x_axis,
                yaxis_title=f"Sum of {y_axis}",
                yaxis=dict(
                    tickformat=',.0f'  # Set tickformat to scientific notation with 2 decimal places
                )
            )
            fig.update_traces(marker_color='green', marker_line=dict(color='black', width=2))
            fig.update_layout(plot_bgcolor='rgba(0, 0, 0, 0)')
            
            fig.show()           
        
        elif graph_type == 'pie':
            
            grouped_df = df.groupby(x_axis)[y_axis].sum().reset_index()

            fig = go.Figure([go.Pie(labels=grouped_df[x_axis], values=grouped_df[y_axis])])
            fig.update_layout(
                title="Pie Chart",
                showlegend=True
            )

            fig.show()         
            
        elif graph_type == 'area':
            grouped_df = df.groupby(x_axis)[y_axis].sum().reset_index()
            
            fig = go.Figure([go.Scatter(x=grouped_df[x_axis], y=grouped_df[y_axis], mode='lines',fill='tozeroy')])
            
            fig.update_layout(
                title="Area chart",
                xaxis_title=x_axis,
                yaxis_title=y_axis,
                yaxis=dict(
                    tickformat=',.0f'  # Set tickformat to scientific notation with 2 decimal places
                )
            )
            fig.update_traces(marker_color='blue', marker_line=dict(color='black', width=2))
            fig.update_layout(plot_bgcolor='rgba(0, 0, 0, 0)')

            fig.show()
        else:
            return 'Invalid graph type selected'

        # Remove grid lines
        fig.update_xaxes(showgrid=False)
        fig.update_yaxes(showgrid=False)

        plot_filename = os.path.join('static', f'plot_{graph_type}.html')
        fig.write_html(plot_filename)
        plot_filenames.append(plot_filename)

    return render_template('plot.html', plot_filenames=plot_filenames, username=username)

@app.route('/tablebasic')
def tablebasic():
    username = session.get("username")
    return render_template('tablebasic.html', username=username)

@app.route('/overproduction')
def overproduction():
    username = session.get("username")
    return render_template('overproduction.html', username=username)

@app.route('/underproduction')
def underproduction():
    username = session.get("username")
    return render_template('underproduction.html', username=username)

@app.route('/optimalproduction')
def optimalproduction():
    username = session.get("username")
    return render_template('optimalproduction.html', username=username)

@app.route('/top1')
def top1():
    username = session.get("username")
    return render_template('top1.html', username=username)

@app.route('/top2')
def top2():
    username = session.get("username")
    return render_template('top2.html', username=username)

@app.route('/top4')
def top4():
    username = session.get("username")
    return render_template('top4.html', username=username)

@app.route('/top5')
def top5():
    username = session.get("username")
    return render_template('top5.html', username=username)

@app.route('/top7')
def top7():
    username = session.get("username")
    return render_template('top7.html', username=username)

@app.route('/top8')
def top8():
    username = session.get("username")
    return render_template('top8.html', username=username)

@app.route('/top9')
def top9():
    username = session.get("username")
    return render_template('top9.html', username=username)

@app.route('/top10')
def top10():
    username = session.get("username")
    return render_template('top10.html', username=username)

@app.route('/top11')
def top11():
    username = session.get("username")
    return render_template('top11.html', username=username)

@app.route('/top12')
def top12():
    username = session.get("username")
    return render_template('top12.html', username=username)

def fabricKgs_charts():
    # Load the data
    df1 = pd.read_csv('top1.csv')
    column1 = 'Year'
    column2 = 'Item Name'
    column3 = 'Fabric Kgs'
    
    # Remove the groupby and sum operations
    chart_df1 = df1[[column1, column2, column3]].reset_index()

    # Bar chart 1
    fig1 = px.bar(chart_df1, x=column1, y=column3, title='Top 5 Products Fabricated each Year',
                labels={column3: 'Fabric Kgs'})
    fig1.update_traces(marker_color='lightgreen', marker_line=dict(color='black', width=2))  # Add border to bars
    fig1.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig1.update_traces(hovertemplate='Year: %{x}<br>Item Name: %{text}<br>Fabric Kgs: %{y:,.2f}<br>',
                       text=chart_df1[column2])
    
    df2 = pd.read_csv('top2.csv')
    column1 = 'Month'
    column2 = 'Item Name'
    column3 = 'Fabric Kgs'
    
    # Remove the groupby and sum operations
    chart_df2 = df2[[column1, column2, column3]].reset_index()

    # Bar chart 2
    fig2 = px.bar(chart_df2, x=column1, y=column3, title='Top 5 Products Fabricated each Month',
                labels={column3: 'Fabric Kgs'})
    fig2.update_traces(marker_color='lightblue', marker_line=dict(color='black', width=2))  # Add border to bars
    fig2.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig2.update_traces(hovertemplate='Month: %{x}<br>Item Name: %{text}<br>Fabric Kgs: %{y:,.2f}<br>',
                       text=chart_df2[column2])
    
    return fig1, fig2
    
    
@app.route('/fabricKgs')
def fabricKgs():
    
    username = session.get("username")
    
    fig1, fig2 = fabricKgs_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    

    return render_template('fabricKgs.html', chart1_json=chart1_json, chart2_json=chart2_json, username=username)


def soldKgs_charts():
    # Load the data
    df1 = pd.read_csv('top4.csv')
    column1 = 'Year'
    column2 = 'Item Name'
    column3 = 'Sold Kgs'
    
    # Remove the groupby and sum operations
    chart_df1 = df1[[column1, column2, column3]].reset_index()

    # Bar chart 1
    fig1 = px.bar(chart_df1, x=column1, y=column3, title='Top 5 Products Sold in Kilograms each Year',
                labels={column3: 'Sold Kgs'})
    fig1.update_traces(marker_color='pink', marker_line=dict(color='black', width=2))  # Add border to bars
    fig1.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig1.update_traces(hovertemplate='Year: %{x}<br>Item Name: %{text}<br>Sold Kgs: %{y:,.2f}<br>',
                       text=chart_df1[column2])
    
    
    df2 = pd.read_csv('top3.csv')
    column1 = 'Month'
    column2 = 'Item Name'
    column3 = 'Sold Kgs'
    
    # Remove the groupby and sum operations
    chart_df2 = df2[[column1, column2, column3]].reset_index()

    # Bar chart 2
    fig2 = px.bar(chart_df2, x=column1, y=column3, title='Top 5 Products Sold in Kilograms each Month',
                labels={column3: 'Sold Kgs'})
    fig2.update_traces(marker_color='lavender', marker_line=dict(color='black', width=2))  # Add border to bars
    fig2.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig2.update_traces(hovertemplate='Month: %{x}<br>Item Name: %{text}<br>Sold Kgs: %{y:,.2f}<br>',
                       text=chart_df2[column2])
    
    df3 = pd.read_csv('top7.csv')
    column1 = 'Month'
    column2 = 'Party Name'
    column3 = 'Sold Kgs'
    
    # Remove the groupby and sum operations
    chart_df3 = df3[[column1, column2, column3]].reset_index()

    # Bar chart 3
    fig3 = px.bar(chart_df3, x=column1, y=column3, title='Top 5 Customers purchased in Kilograms each Month',
                labels={column3: 'Sold Kgs'})
    fig3.update_traces(marker_color='crimson', marker_line=dict(color='black', width=2))  # Add border to bars
    fig3.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig3.update_traces(hovertemplate='Month: %{x}<br>Party Name: %{text}<br>Sold Kgs: %{y:,.2f}<br>',
                       text=chart_df3[column2])
    
    return fig1, fig2, fig3    
    

@app.route('/soldKgs')
def soldKgs():
    
    username = session.get("username")
    
    fig1, fig2, fig3 = soldKgs_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()
    
    return render_template('soldKgs.html', chart1_json=chart1_json, chart2_json=chart2_json,
                           chart3_json=chart3_json, username=username)


def amount_charts():
    # Load the data    
    
    df2 = pd.read_csv('top5.csv')
    column1 = 'Year'
    column2 = 'Item Name'
    column3 = 'Amount'
    
    # Remove the groupby and sum operations
    chart_df2 = df2[[column1, column2, column3]].reset_index()

    # Bar chart 2
    fig2 = px.bar(chart_df2, x=column1, y=column3, title='Top 5 Products Sold in Amount each Year',
                labels={column3: 'Amount'})
    fig2.update_traces(marker_color='khaki', marker_line=dict(color='black', width=2))  # Add border to bars
    fig2.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig2.update_traces(hovertemplate='Year: %{x}<br>Item Name: %{text}<br>Amount: %{y:,.2f}<br>',
                       text=chart_df2[column2])
    
    df3 = pd.read_csv('top8.csv')
    column1 = 'Month'
    column2 = 'Item Name'
    column3 = 'Amount'
    
    # Remove the groupby and sum operations
    chart_df3 = df3[[column1, column2, column3]].reset_index()

    # Bar chart 3
    fig3 = px.bar(chart_df3, x=column1, y=column3, title='Top 5 Products Sold in Amount each Month',
                labels={column3: 'Amount'})
    fig3.update_traces(marker_color='orange', marker_line=dict(color='black', width=2))  # Add border to bars
    fig3.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig3.update_traces(hovertemplate='Month: %{x}<br>Item Name: %{text}<br>Amount: %{y:,.2f}<br>',
                       text=chart_df3[column2])
    
    df4 = pd.read_csv('top11.csv')
    column1 = 'Year'
    column2 = 'State Name'
    column3 = 'Amount'
    
    # Remove the groupby and sum operations
    chart_df4 = df4[[column1, column2, column3]].reset_index()

    # Bar chart 3
    fig4 = px.bar(chart_df4, x=column1, y=column3, title='Top 5 States purchased in Amount each Year',
                labels={column3: 'Amount'})
    fig4.update_traces(marker_color='olive', marker_line=dict(color='black', width=2))  # Add border to bars
    fig4.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig4.update_traces(hovertemplate='Year: %{x}<br>State Name: %{text}<br>Amount: %{y:,.2f}<br>',
                       text=chart_df4[column2])
    
    df5 = pd.read_csv('top12.csv')
    column1 = 'Year'
    column2 = 'Party Name'
    column3 = 'Amount'
    
    # Remove the groupby and sum operations
    chart_df5 = df5[[column1, column2, column3]].reset_index()

    # Bar chart 3
    fig5 = px.bar(chart_df5, x=column1, y=column3, title='Top 5 Customers purchased in Amount each Year',
                labels={column3: 'Amount'})
    fig5.update_traces(marker_color='tan', marker_line=dict(color='black', width=2))  # Add border to bars
    fig5.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig5.update_traces(hovertemplate='Year: %{x}<br>Party Name: %{text}<br>Amount: %{y:,.2f}<br>',
                       text=chart_df5[column2])
    
    return fig2, fig3, fig4, fig5  
    


@app.route('/amount')
def amount():
    
    username = session.get("username")
    
    fig2, fig3, fig4, fig5 = amount_charts()

    # Convert the figures to JSON format for embedding in the template
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()
    chart4_json = fig4.to_json()
    chart5_json = fig5.to_json()
    
    return render_template('amount.html', chart2_json=chart2_json, chart3_json=chart3_json,
                           chart4_json=chart4_json, chart5_json=chart5_json,
                           username=username)


def generate_charts():
    # Load the data
    df = pd.read_csv('MainData.csv')
    

    # Column names
    value_column_name1 = 'FABRIC KGS'
    value_column_name2 = 'FABRIC MTRS'
    value_column_name3 = 'SOLD KGS'
    value_column_name4 = 'SOLD MTRS'
    value_column_name5 = 'RATE'
    value_column_name6 = 'AMOUNT'
    
    label_column_name1 = 'ITEM ID'
    label_column_name2 = 'TIME ID'
    label_column_name3 = 'TIME M ID'
    label_column_name4 = 'TIME Y ID'
    label_column_name5 = 'STATE ID'
    label_column_name6 = 'PARTY ID'

    kpi1 = round(df['FABRIC KGS'].sum(), 3)
    kpi2 = round(df['SOLD KGS'].sum(), 3)
    kpi3 = round(df['AMOUNT'].sum(), 0)
    kpi4 = df['ITEM ID'].nunique()
    

    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df1 = df.groupby(label_column_name4)[value_column_name6].sum().reset_index()

    # Donut chart 1
    fig1 = px.pie(grouped_df1, values=value_column_name6, names=label_column_name4, title='Sales in Amount for each Year',
                hole=0.5)  # Set the 'hole' parameter to create a donut chart

    # Add border for each segment in the chart
    fig1.update_traces(marker=dict(line=dict(color='black', width=2)))
    # Add hover effect with popup
    fig1.update_traces(hovertemplate="%{label}: %{value}")
    
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df2 = df.groupby(label_column_name4)[label_column_name1].nunique().reset_index()
    
    # Bar chart 1
    fig2 = px.bar(grouped_df2, x=label_column_name4, y=label_column_name1, title='Items Fabricated & Sold each Year',
                  labels={label_column_name1: 'Value'})
    fig2.update_traces(marker_color='yellow', marker_line=dict(color='darkgoldenrod', width=2))  # Set the color of the bars to yellow
    fig2.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Year',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df2[label_column_name4],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df2[label_column_name4]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df3 = df.groupby(label_column_name2)[value_column_name6].sum().reset_index()
    
    # Manually enter x-axis labels
    x_axis_labels = ['4/2019', '5/2019', '6/2019', '7/2019', '8/2019', '9/2019', '10/2019', '11/2019', '12/2019', 
                     '1/2020', '2/2020', '3/2020', '4/2020', '5/2020', '6/2020', '7/2020', '8/2020', '9/2020', '10/2020', '11/2020', '12/2020',
                     '1/2021', '2/2021', '3/2021', '4/2021', '5/2021', '6/2021', '7/2021', '8/2021', '9/2021', '10/2021', '11/2021', '12/2021',
                     '1/2022', '2/2022', '3/2022', '4/2022', '5/2022', '6/2022', '7/2022', '8/2022', '9/2022', '10/2022', '11/2022', '12/2022',
                     '1/2023', '2/2023', '3/2023']  # Replace with your desired x-axis labels

    
    # Line chart 1
    fig3 = go.Figure()
    fig3.add_trace(go.Scatter(
        x=grouped_df3[label_column_name2],
        y=grouped_df3[value_column_name6],
        mode='lines',
        name='Sum of Amount',
        line=dict(color='orange',width=3),
        hovertemplate='MM/YYYY: %{x}<br>AMOUNT: %{y:,.0f}'  # Use &#8226; for bullet point symbol
    ))
    fig3.update_layout(
        title='Sales in Amount for each Year and Month',
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        xaxis=dict(
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df3[label_column_name2],  # Set the tick values to the 'TIME ID' values
            ticktext=x_axis_labels,  # Set the tick text to the 'TIME ID' values
            title='Month & Year',  # Set x-axis title
        ),
        yaxis_title='AMOUNT',  # Set y-axis title
        yaxis=dict(
            tickformat=',.0f'  # Format y-axis labels as standard numerical format
        )
    )
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df4 = df.groupby(label_column_name4)[value_column_name3].sum().reset_index()
    
    # Bar chart 2
    fig4 = px.bar(grouped_df4, x=label_column_name4, y=value_column_name3, title='Sales in Kilograms for each Year',
                  labels={label_column_name4: 'TIME Y ID'})
    fig4.update_traces(marker_color='green', marker_line=dict(color='lightgreen', width=2))  # Set the color of the bars to yellow
    fig4.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Year',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df4[label_column_name4],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df4[label_column_name4]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig4.update_traces(hovertemplate='YEAR: %{x}<br>SOLD KGS: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df1 = df.groupby(label_column_name4)[value_column_name6].sum().reset_index()    
    
    # Bar chart 3
    fig5 = px.bar(grouped_df1, x=label_column_name4, y=value_column_name6, title='Sales in Amount for each Year',
                  labels={label_column_name4: 'TIME Y ID'})
    fig5.update_traces(marker_color='green', marker_line=dict(color='lightgreen', width=2))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig5.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Year',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df1[label_column_name4],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df1[label_column_name4]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig5.update_traces(hovertemplate='YEAR: %{x}<br>AMOUNT: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df5 = df.groupby(label_column_name3)[value_column_name3].sum().reset_index()
    
    # Bar chart 4
    fig6 = px.bar(grouped_df5, x=label_column_name3, y=value_column_name3, title='Sales in Kilograms for each Month',
                  labels={label_column_name3: 'TIME M ID'})
    fig6.update_traces(marker_color='red', marker_line=dict(color='black', width=1))  # Set the color of the bars to yellow
    fig6.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Month',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df5[label_column_name3],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df5[label_column_name3]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig6.update_traces(hovertemplate='MONTH: %{x}<br>SOLD KGS: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df6 = df.groupby(label_column_name3)[value_column_name6].sum().reset_index()    
    
    # Bar chart 5
    fig7 = px.bar(grouped_df6, x=label_column_name3, y=value_column_name6, title='Sales in Amount for each Month',
                  labels={label_column_name3: 'TIME M ID'})
    fig7.update_traces(marker_color='red', marker_line=dict(color='black', width=1))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig7.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Month',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df6[label_column_name3],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df6[label_column_name3]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig7.update_traces(hovertemplate='MONTH: %{x}<br>AMOUNT: %{y:,.2f}')
    
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES' for the bar chart
    grouped_df7 = df.groupby(label_column_name5)[value_column_name3].sum().reset_index()

    # Bar chart 6
    fig8 = go.Figure()

    fig8.add_trace(go.Bar(
        x=grouped_df7[label_column_name5],
        y=grouped_df7[value_column_name3],
        name='Sales in Kilograms',
        marker_color='orange',
        marker_line=dict(color='black', width=1)
    ))

    fig8.update_layout(
        title='Sales in Kilograms and Amount for each State',
        xaxis=dict(title=label_column_name5),
        yaxis=dict(title=value_column_name3, tickformat=',d'),
        plot_bgcolor='rgba(0, 0, 0, 0)',
        showlegend=False  # Remove the legend
    )

    # Group the data by 'LABEL' and calculate the sum of 'VALUES' for the line chart
    grouped_df8 = df.groupby(label_column_name5)[value_column_name6].sum().reset_index()

    # Line chart (added as a trace to the existing figure)
    fig8.add_trace(go.Scatter(
        x=grouped_df8[label_column_name5],
        y=grouped_df8[value_column_name6],
        name='Sales in Amount',
        yaxis='y2',
        line=dict(color='blue')
    ))

    fig8.update_layout(
        yaxis2=dict(title=value_column_name6, overlaying='y', side='right', tickformat=',d'),
        showlegend=True,  # Add legend to the chart
        legend=dict(x=0.05, xanchor='left'),  # Move legend slightly towards the left
        xaxis=dict(
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df8[label_column_name5],  # Set the tick values to the 'State' values
            ticktext=grouped_df8[label_column_name5],
            title='State'  # Set x-axis title to 'State'
        )
    )

    # Add x-axis and y-axis values to the hover tooltip for both traces
    fig8.update_traces(
        hovertemplate='STATE: %{x}<br>SOLD KGS: %{y:,.2f}',
        selector=dict(type='bar')
    )
    fig8.update_traces(
        hovertemplate='STATE: %{x}<br>AMOUNT: %{y:,.2f}',
        selector=dict(type='scatter')
    )

    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df9 = df.groupby(label_column_name3)[value_column_name6].sum().reset_index()
    
    # Top 5 Bar Chart 1
    top5_df1 = grouped_df9.nlargest(5, value_column_name6)
    fig9 = px.bar(top5_df1, x=label_column_name3, y=value_column_name6, title='Top 5 Months in Total Sales',
                  labels={value_column_name3: 'TIME M ID'})
    fig9.update_traces(marker_color='red', marker_line=dict(color='black', width=2))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig9.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Month',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df9[label_column_name3],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df9[label_column_name3]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig9.update_traces(hovertemplate='MONTH: %{x}<br>AMOUNT: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df10 = df.groupby(label_column_name5)[value_column_name6].sum().reset_index()
    
    # Top 5 Bar Chart 2
    top5_df2 = grouped_df10.nlargest(5, value_column_name6)
    fig10 = px.bar(top5_df2, x=label_column_name5, y=value_column_name6, title='Top 5 State purchased in Amount',
                  labels={value_column_name6: 'AMOUNT'})
    fig10.update_traces(marker_color='pink', marker_line=dict(color='red', width=2))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig10.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='States',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df10[label_column_name5],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df10[label_column_name5]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig10.update_traces(hovertemplate='STATE: %{x}<br>AMOUNT: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df11 = df.groupby(label_column_name6)[value_column_name6].sum().reset_index()
    
    # Top 5 Bar Chart 3
    top5_df3 = grouped_df11.nlargest(5, value_column_name6)
    fig11 = px.bar(top5_df3, x=label_column_name6, y=value_column_name6, title='Top 5 Party purchased in Amount',
                  labels={value_column_name6: 'AMOUNT'})
    fig11.update_traces(marker_color='purple', marker_line=dict(color='black', width=1))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig11.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Party',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df11[label_column_name6],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df11[label_column_name6]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig11.update_traces(hovertemplate='PARTY: %{x}<br>AMOUNT: %{y:,.2f}')
    
    # 
    df1 = pd.read_csv('O U P.csv')
    column1 = 'TIME ID'
    column2 = 'O U P'
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df1 = df1.groupby(column1)[column2].sum().reset_index()

    # Manually enter x-axis labels
    x_axis_labels = ['4/2019', '5/2019', '6/2019', '7/2019', '8/2019', '9/2019', '10/2019', '11/2019', '12/2019', 
                     '1/2020', '2/2020', '3/2020', '4/2020', '5/2020', '6/2020', '7/2020', '8/2020', '9/2020', '10/2020', '11/2020', '12/2020',
                     '1/2021', '2/2021', '3/2021', '4/2021', '5/2021', '6/2021', '7/2021', '8/2021', '9/2021', '10/2021', '11/2021', '12/2021',
                     '1/2022', '2/2022', '3/2022', '4/2022', '5/2022', '6/2022', '7/2022', '8/2022', '9/2022', '10/2022', '11/2022', '12/2022',
                     '1/2023', '2/2023', '3/2023']  # Replace with your desired x-axis labels

    # Candle Bar Chart 1
    fig12 = px.bar(grouped_df1, x=column1, y=column2, title='Over and Under Production in Kilograms for each Month & Year',
                labels={column1: 'Month & Year', column2: 'PRODUCTION'})
    fig12.update_traces(marker_color='crimson', marker_line=dict(color='black', width=2))  # Set the color of the bars to yellow
    fig12.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df1[column1],  # Set the tick values to the unique values in the 'TIME ID' column
            ticktext=x_axis_labels  # Set the tick text to the manually entered labels
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig12.update_traces(hovertemplate='MM/YYYY: %{x}<br>PRODUCTION: %{y:,.2f}')


    return kpi1, kpi2, kpi3, kpi4, fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8, fig9, fig10, fig11, fig12


@app.route('/index3')
def index3():
    
    username = session.get("username") 
    
    kpi1, kpi2, kpi3, kpi4, fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8, fig9, fig10, fig11, fig12 = generate_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()
    chart4_json = fig4.to_json()
    chart5_json = fig5.to_json()
    chart6_json = fig6.to_json()
    chart7_json = fig7.to_json()
    chart8_json = fig8.to_json()
    chart9_json = fig9.to_json()
    chart10_json = fig10.to_json()
    chart11_json = fig11.to_json()
    chart12_json = fig12.to_json()
    
    return render_template('index3.html',username=username, 
                           chart1_json=chart1_json, chart2_json=chart2_json,
                           chart3_json=chart3_json, chart4_json=chart4_json,
                           chart5_json=chart5_json, chart6_json=chart6_json,
                           chart7_json=chart7_json, chart8_json=chart8_json,
                           chart9_json=chart9_json, chart10_json=chart10_json,
                           chart11_json=chart11_json, chart12_json=chart12_json,
                           kpi1=kpi1, kpi2=kpi2, kpi3=kpi3, kpi4=kpi4)
    

def generate_bar_charts():
    # Load the data
    df = pd.read_csv('MainData.csv')

    # Column names
    value_column_name1 = 'FABRIC KGS'
    value_column_name2 = 'FABRIC MTRS'
    value_column_name3 = 'SOLD KGS'
    value_column_name4 = 'SOLD MTRS'
    value_column_name5 = 'RATE'
    value_column_name6 = 'AMOUNT'
    
    label_column_name1 = 'ITEM ID'
    label_column_name2 = 'TIME ID'
    label_column_name3 = 'TIME M ID'
    label_column_name4 = 'TIME Y ID'
    label_column_name5 = 'STATE ID'
    label_column_name6 = 'PARTY ID'
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df1 = df.groupby(label_column_name3)[label_column_name1].nunique().reset_index()
    
    # Bar chart 1
    fig1 = px.bar(grouped_df1, x=label_column_name3, y=label_column_name1, title='Items Fabricated & Sold each Month',
                  labels={label_column_name1: 'Value'})
    fig1.update_traces(marker_color='yellow', marker_line=dict(color='darkgoldenrod', width=2))  # Set the color of the bars to yellow
    fig1.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Month',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df1[label_column_name3],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df1[label_column_name3]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES' for the bar chart
    grouped_df2 = df.groupby(label_column_name4)[value_column_name3].sum().reset_index()
    
    # Bar chart 2
    fig2 = go.Figure()

    fig2.add_trace(go.Bar(
        x=grouped_df2[label_column_name4],
        y=grouped_df2[value_column_name3],
        name='Sales in Kilograms',
        marker_color='pink',
        marker_line=dict(color='black', width=2)
    ))

    fig2.update_layout(
        title='Sales & Fabrication in Kilograms for each Year',
        xaxis=dict(title='Year',
                    tickmode='array',  # Set the tick mode to 'array'
                    tickvals=grouped_df2[label_column_name4],  # Set the tick values to the unique values in the 'LABEL' column
                    ticktext=grouped_df2[label_column_name4]),
        yaxis=dict(title=value_column_name3, tickformat=',d'),
        plot_bgcolor='rgba(0, 0, 0, 0)',
        showlegend=False  # Remove the legend
    )

    # Group the data by 'LABEL' and calculate the sum of 'VALUES' for the line chart
    grouped_df3 = df.groupby(label_column_name4)[value_column_name1].sum().reset_index()

    # Line chart (added as a trace to the existing figure)
    fig2.add_trace(go.Scatter(
        x=grouped_df3[label_column_name4],
        y=grouped_df3[value_column_name1],
        name='Fabrication in Kilograms',
        yaxis='y2',
        line=dict(color='red')
    ))

    fig2.update_layout(
        yaxis2=dict(title=value_column_name1, overlaying='y', side='right', tickformat=',d')
    )

    # Add x-axis and y-axis values to the hover tooltip for both traces
    fig2.update_traces(
        hovertemplate='YEAR: %{x}<br>SOLD KGS: %{y:,.2f}',
        selector=dict(type='bar')
    )
    fig2.update_traces(
        hovertemplate='YEAR: %{x}<br>FABRIC KGS: %{y:,.2f}',
        selector=dict(type='scatter')
    )
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES' for the bar chart
    grouped_df4 = df.groupby(label_column_name3)[value_column_name3].sum().reset_index()
    
    # Bar chart 3
    fig3 = go.Figure()

    fig3.add_trace(go.Bar(
        x=grouped_df4[label_column_name3],
        y=grouped_df4[value_column_name3],
        name='Sales in Kilograms',
        marker_color='lightblue',
        marker_line=dict(color='blue', width=2)
    ))

    fig3.update_layout(
        title='Sales & Fabrication in Kilograms for each Month',
        xaxis=dict(title='Month',
                    tickmode='array',  # Set the tick mode to 'array'
                    tickvals=grouped_df4[label_column_name3],  # Set the tick values to the unique values in the 'LABEL' column
                    ticktext=grouped_df4[label_column_name3]),
        yaxis=dict(title=value_column_name3, tickformat=',d'),
        plot_bgcolor='rgba(0, 0, 0, 0)',
        showlegend=False  # Remove the legend
    )

    # Group the data by 'LABEL' and calculate the sum of 'VALUES' for the line chart
    grouped_df5 = df.groupby(label_column_name3)[value_column_name1].sum().reset_index()

    # Line chart (added as a trace to the existing figure)
    fig3.add_trace(go.Scatter(
        x=grouped_df5[label_column_name3],
        y=grouped_df5[value_column_name1],
        name='Fabrication in Kilograms',
        yaxis='y2',
        line=dict(color='orange')
    ))

    fig3.update_layout(
        yaxis2=dict(title=value_column_name1, overlaying='y', side='right', tickformat=',d')
    )

    # Add x-axis and y-axis values to the hover tooltip for both traces
    fig3.update_traces(
        hovertemplate='MONTH: %{x}<br>SOLD KGS: %{y:,.2f}',
        selector=dict(type='bar')
    )
    fig3.update_traces(
        hovertemplate='MONTH: %{x}<br>FABRIC KGS: %{y:,.2f}',
        selector=dict(type='scatter')
    )
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df6 = df.groupby(label_column_name5)[value_column_name3].sum().reset_index()

    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df7 = df.groupby(label_column_name5)[value_column_name6].sum().reset_index()
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df8 = df.groupby(label_column_name5)[value_column_name4].sum().reset_index()

    # Bar Chart 4
    # Create a new figure
    fig4 = go.Figure()

    # Add the second bar trace for 'Sales in Amount'
    fig4.add_trace(go.Bar(
        x=grouped_df7[label_column_name5],
        y=grouped_df7[value_column_name6],
        name='Sales in Amount',
        marker_color='blue',
        marker_line=dict(color='black', width=2),
        hovertemplate='STATE: %{x}<br>AMOUNT: %{y:,.2f}'
    ))
    
    # Add the first bar trace for 'Sales in Meters'
    fig4.add_trace(go.Bar(
        x=grouped_df8[label_column_name5],
        y=grouped_df8[value_column_name4],
        name='Sales in Meters',
        marker_color='red',
        marker_line=dict(color='black', width=2),
        hovertemplate='STATE: %{x}<br>SOLD MTRS: %{y:,.2f}'
    ))
    
    # Add the first bar trace for 'Sales in Kilograms'
    fig4.add_trace(go.Bar(
        x=grouped_df6[label_column_name5],
        y=grouped_df6[value_column_name3],
        name='Sales in Kilograms',
        marker_color='green',
        marker_line=dict(color='black', width=2),
        hovertemplate='STATE: %{x}<br>SOLD KGS: %{y:,.2f}'
    ))
    
    # Update the layout of the figure
    fig4.update_layout(
        barmode='group',
        title='Sales in Amount Meters & Kilograms for each State',
        xaxis=dict(title='States'),
        yaxis=dict(tickformat=',d'),
        plot_bgcolor='rgba(0, 0, 0, 0)'
    )    

    # Bar Chart 5
    years = ['2019', '2020', '2021', '2022', '2023']
    soldmtrs = [14732637, 22611505, 24970044, 17354451, 4178933]
    fabricmtrs = [15266853, 20126895, 27171707, 18727601]
    soldkgs = [1018510, 1733435, 1950705, 1448844, 428140]
    fabrickgs = [1007159, 1284771, 1756254, 1277948, 229122]

    stackedChartData = [
        go.Bar(x=years, y=soldmtrs, name='SOLD MTRS', marker=dict(color='yellow')),
        go.Bar(x=years, y=fabricmtrs, name='FABRIC MTRS', marker=dict(color='red')),
        go.Bar(x=years, y=soldkgs, name='SOLD KGS', marker=dict(color='green')),
        go.Bar(x=years, y=fabrickgs, name='FABRIC KGS', marker=dict(color='blue'))
    ]

    layout = go.Layout(
        title='Fabricated and Sold each Year',
        xaxis=dict(title='Year'),
        yaxis=dict(title='Values', tickformat=','),
        barmode='stack',
        showlegend=False,
        plot_bgcolor='rgba(0,0,0,0)'
    )

    fig5 = go.Figure(data=stackedChartData, layout=layout)
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df9 = df.groupby(label_column_name5)[value_column_name3].sum().reset_index()
    
    # Top 5 Bar Chart 1
    top5_df1 = grouped_df9.nlargest(5, value_column_name3)
    fig6 = px.bar(top5_df1, x=label_column_name5, y=value_column_name3, title='Top 5 State purchased in Kilograms',
                  labels={value_column_name3: 'KILOGRAMS'})
    fig6.update_traces(marker_color='lightgreen', marker_line=dict(color='green', width=2))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig6.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='State',
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df9[label_column_name5],  # Set the tick values to the unique values in the 'LABEL' column
            ticktext=grouped_df9[label_column_name5]  # Set the tick text to the unique values in the 'LABEL' column
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig6.update_traces(hovertemplate='STATE: %{x}<br>SOLD KGS: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df10 = df.groupby(label_column_name6)[value_column_name6].sum().reset_index()
    
    # Top 10 Bar Chart 1
    top10_df1 = grouped_df10.nlargest(10, value_column_name6)
    fig7 = px.bar(top10_df1, x=label_column_name6, y=value_column_name6, title='Top 10 Party purchased in Amount',
                  labels={value_column_name6: 'AMOUNT'})
    fig7.update_traces(marker_color='yellow', marker_line=dict(color='black', width=1))  # Add border to bars
                                                                                        # Set the color of the bars to yellow
    fig7.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title='Party'
        )
    )
    # Add x-axis and y-axis values to the hover tooltip
    fig7.update_traces(hovertemplate='PARTY: %{x}<br>AMOUNT: %{y:,.2f}')
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df11 = df.groupby(label_column_name2)[label_column_name6].nunique().reset_index()
    
    # Manually enter x-axis labels
    x_axis_labels = ['4/2019', '5/2019', '6/2019', '7/2019', '8/2019', '9/2019', '10/2019', '11/2019', '12/2019', 
                     '1/2020', '2/2020', '3/2020', '4/2020', '5/2020', '6/2020', '7/2020', '8/2020', '9/2020', '10/2020', '11/2020', '12/2020',
                     '1/2021', '2/2021', '3/2021', '4/2021', '5/2021', '6/2021', '7/2021', '8/2021', '9/2021', '10/2021', '11/2021', '12/2021',
                     '1/2022', '2/2022', '3/2022', '4/2022', '5/2022', '6/2022', '7/2022', '8/2022', '9/2022', '10/2022', '11/2022', '12/2022',
                     '1/2023', '2/2023', '3/2023']  # Replace with your desired x-axis labels
    
    # Bar chart 6
    fig8 = px.bar(grouped_df11, x=label_column_name2, y=label_column_name6, title='Customers purchsed each Year and Month',
                  labels={label_column_name6: 'Value'})
    fig8.update_traces(marker_color='khaki', marker_line=dict(color='black', width=2))  # Set the color of the bars to yellow
    fig8.update_layout(
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        yaxis=dict(
            title = "Value",
            tickformat=',d'  # Format y-axis labels in standard numerical format
        ),
        xaxis=dict(
            title = "Month & Year",
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df11[label_column_name2],  # Set the tick values to the unique values in the 'TIME ID' column
            ticktext=x_axis_labels  # Set the tick text to the manually entered labels
        )
    )
    
    return fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8


@app.route('/barchart')
def barchart():
    
    username = session.get("username")
    
    fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8 = generate_bar_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()
    chart4_json = fig4.to_json()
    chart5_json = fig5.to_json()
    chart6_json = fig6.to_json()
    chart7_json = fig7.to_json()
    chart8_json = fig8.to_json()
        
    return render_template('barchart.html', chart1_json=chart1_json, chart2_json=chart2_json,
                           chart3_json=chart3_json, chart4_json=chart4_json,
                           chart5_json=chart5_json, chart6_json=chart6_json,
                           chart7_json=chart7_json, chart8_json=chart8_json,
                           username=username)


def generate_line_charts():
    # Load the data
    df = pd.read_csv('MainData.csv')
    
    # Column names
    value_column_name1 = 'FABRIC KGS'
    value_column_name2 = 'FABRIC MTRS'
    value_column_name3 = 'SOLD KGS'
    value_column_name4 = 'SOLD MTRS'
    value_column_name5 = 'RATE'
    value_column_name6 = 'AMOUNT'
    
    label_column_name1 = 'ITEM ID'
    label_column_name2 = 'TIME ID'
    label_column_name3 = 'TIME M ID'
    label_column_name4 = 'TIME Y ID'
    label_column_name5 = 'STATE ID'
    label_column_name6 = 'PARTY ID'
    
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df1 = df.groupby(label_column_name3)[value_column_name2].sum().reset_index()
    grouped_df2 = df.groupby(label_column_name3)[value_column_name4].sum().reset_index()

    # Line Chart 2
    fig1 = go.Figure()

    # Add line plot for 'value_column_name2'
    fig1.add_trace(
        go.Scatter(
            x=grouped_df1[label_column_name3],
            y=grouped_df1[value_column_name2],
            mode='lines',
            name='Fabricated in Meters',
            line=dict(color='purple', width=3),
            hovertemplate='MONTH: %{x}<br>FABRIC MTRS: %{y:,.2f}'
        )
    )

    # Add line plot for 'value_column_name4'
    fig1.add_trace(
        go.Scatter(
            x=grouped_df2[label_column_name3],
            y=grouped_df2[value_column_name4],
            mode='lines',
            name='Sales in Meters',
            line=dict(color='yellow', width=3),
            hovertemplate='MONTH: %{x}<br>SOLD MTRS: %{y:,.2f}'
        )
    )

    # Update layout
    fig1.update_layout(
        title='Sales and Fabrication in Meters for each Month',
        xaxis=dict(title='Month'),
        yaxis=dict(title='Meters', tickformat=',d'),
        plot_bgcolor='rgba(0, 0, 0, 0)'  # Set the background color to transparent
    )    
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df3 = df.groupby(label_column_name2)[label_column_name1].nunique().reset_index()
    
    # Manually enter x-axis labels
    x_axis_labels = ['4/2019', '5/2019', '6/2019', '7/2019', '8/2019', '9/2019', '10/2019', '11/2019', '12/2019', 
                     '1/2020', '2/2020', '3/2020', '4/2020', '5/2020', '6/2020', '7/2020', '8/2020', '9/2020', '10/2020', '11/2020', '12/2020',
                     '1/2021', '2/2021', '3/2021', '4/2021', '5/2021', '6/2021', '7/2021', '8/2021', '9/2021', '10/2021', '11/2021', '12/2021',
                     '1/2022', '2/2022', '3/2022', '4/2022', '5/2022', '6/2022', '7/2022', '8/2022', '9/2022', '10/2022', '11/2022', '12/2022',
                     '1/2023', '2/2023', '3/2023']  # Replace with your desired x-axis labels
    
    # Line chart 2
    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(
        x=grouped_df3[label_column_name2],
        y=grouped_df3[label_column_name1],
        mode='lines',
        name='ITEM ID Count',
        line=dict(color='hotpink', width=4),
        hovertemplate='MM/YYYY: %{x}<br>Count: &#8226; %{y:,.0f}'  # Use &#8226; for bullet point symbol
    ))
    fig2.update_layout(
        title='Items Fabricated and Sold each Month and Year',
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        xaxis_title='Month & Year',  # Set x-axis title
        yaxis_title='Value',  # Set y-axis title
        xaxis=dict(
            tickmode='array',  # Set the tick mode to 'array'
            tickvals=grouped_df3[label_column_name2],  # Set the tick values to the 'TIME ID' values
            ticktext=x_axis_labels,  # Set the tick text to the 'TIME ID' values
            title='Month & Year',  # Set x-axis title
        ),
        yaxis=dict(
            tickformat=',.0f'  # Format y-axis labels as standard numerical format
        )
    )
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df4 = df.groupby(label_column_name5)[label_column_name6].nunique().reset_index()
    
    # Line chart 3
    fig3 = go.Figure()
    fig3.add_trace(go.Scatter(
        x=grouped_df4[label_column_name5],
        y=grouped_df4[label_column_name6],
        mode='lines',
        name='Customers from each State',
        line=dict(color='forestgreen', width=4),
        hovertemplate='STATE: %{x}<br>Count: &#8226; %{y:,.0f}'  # Use &#8226; for bullet point symbol
    ))
    fig3.update_layout(
        title='Customers from each State',
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Set the background color to transparent
        xaxis_title='States',  # Set x-axis title
        yaxis_title='Value',  # Set y-axis title
        yaxis=dict(
            tickformat=',.0f'  # Format y-axis labels as standard numerical format
        )
    )
    
    
    return fig1, fig2, fig3


@app.route('/linechart')
def linechart():
    
    username = session.get("username")
    
    fig1, fig2, fig3 = generate_line_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()

        
    return render_template('linechart.html', chart1_json=chart1_json, chart2_json=chart2_json,
                           chart3_json=chart3_json,
                           username=username)


def generate_pie_charts():
    # Load the data
    df = pd.read_csv('MainData.csv')

    # Column names
    value_column_name1 = 'FABRIC KGS'
    value_column_name2 = 'FABRIC MTRS'
    value_column_name3 = 'SOLD KGS'
    value_column_name4 = 'SOLD MTRS'
    value_column_name5 = 'RATE'
    value_column_name6 = 'AMOUNT'
    
    label_column_name1 = 'ITEM ID'
    label_column_name2 = 'TIME ID'
    label_column_name3 = 'TIME M ID'
    label_column_name4 = 'TIME Y ID'
    label_column_name5 = 'STATE ID'
    label_column_name6 = 'PARTY ID'
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df1 = df.groupby(label_column_name4)[label_column_name5].nunique().reset_index()

    # Donut chart 1
    fig1 = px.pie(grouped_df1, values=label_column_name5, names=label_column_name4, title='Percentage of States annual purchase',
                hole=0.5, color_discrete_sequence=px.colors.qualitative.Set1)  # Set the 'hole' parameter to create a donut chart

    # Add border for each segment in the chart
    fig1.update_traces(marker=dict(line=dict(color='black', width=2)))
    # Add hover effect with popup
    fig1.update_traces(hovertemplate="%{label}: %{value}")
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df2 = df.groupby(label_column_name3)[label_column_name5].nunique().reset_index()

    # Donut chart 2
    fig2 = px.pie(grouped_df2, values=label_column_name5, names=label_column_name3, title='Percentage of States monthly purchase',
                hole=0.5, color_discrete_sequence=px.colors.qualitative.Set1)  # Set the 'hole' parameter to create a donut chart

    # Add border for each segment in the chart
    fig2.update_traces(marker=dict(line=dict(color='black', width=2)))
    # Add hover effect with popup
    fig2.update_traces(hovertemplate="%{label}: %{value}")
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df3 = df.groupby(label_column_name4)[label_column_name6].nunique().reset_index()

    # Pie chart 1
    fig3 = px.pie(grouped_df3, values=label_column_name6, names=label_column_name4, title='Percentage of Customers annual purchase',
                  color_discrete_sequence=px.colors.qualitative.Set1)  # Set the 'hole' parameter to create a donut chart

    # Add border for each segment in the chart
    fig3.update_traces(marker=dict(line=dict(color='white', width=2)))
    # Add hover effect with popup
    fig3.update_traces(hovertemplate="%{label}: %{value}")
    
    # Group the data by 'LABEL' and calculate the sum of 'VALUES'
    grouped_df4 = df.groupby(label_column_name3)[label_column_name6].nunique().reset_index()

    # Pie chart 2
    fig4 = px.pie(grouped_df4, values=label_column_name6, names=label_column_name3, title='Percentage of Customers monthly purchase',
                  color_discrete_sequence=px.colors.qualitative.Set1)  # Set the 'hole' parameter to create a donut chart

    # Add border for each segment in the chart
    fig4.update_traces(marker=dict(line=dict(color='white', width=2)))
    # Add hover effect with popup
    fig4.update_traces(hovertemplate="%{label}: %{value}")
    
    return fig1, fig2, fig3, fig4


@app.route('/piechart')
def piechart():
    
    username = session.get("username")
    
    fig1, fig2, fig3, fig4 = generate_pie_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()
    chart4_json = fig4.to_json()
    
    return render_template('piechart.html', chart1_json=chart1_json, chart2_json=chart2_json,
                           chart4_json=chart4_json, chart3_json=chart3_json,
                           username=username)


def generate_kpi_charts():
    
    # Chart 1
    # Sample data for the pie chart
    labels =  ['YES', 'NO']
    values =  ['67.76', '32.23']

    # Create a pie chart
    fig1 = go.Figure(data=[go.Pie(labels=labels, values=values)])
    fig1.update_layout(title='Customer Retention Rate')

    # Chart 2
    # Create a DataFrame with the data
    df = pd.DataFrame({
        "Category": ["Total Amount", "Total Sold Kgs", "Total Sold (Kgs + Mtrs)"],
        "Item": ["SF54 BLUE - West Bengal - ANANTADEB MADANMOHAN & CO.,", 
                 "HDPE-HaldiaT9 - Karnataka - RUDRAPPA", 
                 "HF54 BLUE - Odisha - PATRA ENTERPRISES"],
        "Percentage": [42, 56, 57]
    })

    # Create a stacked bar chart
    fig2 = px.bar(df, x="Category", y="Percentage", color="Percentage", barmode="stack")

    # Set the text of the bars to the percentage values
    fig2.update_traces(text=df["Percentage"], textposition="outside")
    
    fig2.update_traces(hovertemplate='Category: %{x}<br>Item State Party Name: %{text}<br>Percentage: %{y:,.2f}<br>',
                       text=df["Item"])
        
    fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)")
    fig2.update_layout(title="Share in sales")
    
    
    # Chart 3
    # Create a DataFrame with the data
    df1 = pd.DataFrame({
        "Year": ["2019", "2020", "2021", "2022", "2023"],
        "Item": ["West Bengal - SF54 BLUE", "West Bengal - SF54 BLUE", "West Bengal - SF54 BLUE", 
                 "Karnataka - SF104 GREEN", "Karnataka - HDPE-HaldiaT9"],
        "Amount": [25481000, 30213600, 20907220, 15563290, 5380000]
    })

    # Create a stacked bar chart
    fig3 = px.bar(df1, x="Year", y="Amount", color="Amount", barmode="stack")

    # Set the text of the bars to the percentage values
    fig3.update_traces(text=df1["Amount"], textposition="outside")
    
    fig3.update_traces(hovertemplate='Year: %{x}<br>State Item Name: %{text}<br>Amount: %{y:,.2f}<br>',
                       text=df1["Item"])
        
    fig3.update_layout(plot_bgcolor="rgba(0,0,0,0)")
    fig3.update_layout(title="Top Products purchased each Year with respect to its State")
        
    return fig1, fig2, fig3


@app.route('/kpi')
def kpi():
    
    username = session.get("username")
    
    fig1, fig2, fig3 = generate_kpi_charts()

    # Convert the figures to JSON format for embedding in the template
    chart1_json = fig1.to_json()
    chart2_json = fig2.to_json()
    chart3_json = fig3.to_json()
    
    return render_template('kpi.html', username=username,
                           chart1_json=chart1_json, chart2_json=chart2_json,
                           chart3_json=chart3_json)

if __name__=="__main__":
    app.run(debug=True)
    