from flask import Flask, render_template, request, redirect, session, url_for, flash
import boto3
import uuid
import os
import hashlib
from decimal import Decimal
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'ap-south-1')
DYNAMODB_USERS_TABLE = 'Users'
DYNAMODB_EVENTS_TABLE = 'Events'
DYNAMODB_TICKETS_TABLE = 'Tickets'
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')  


# Set up AWS session and services
session_boto = boto3.Session(
    region_name=AWS_REGION,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

dynamodb = session_boto.resource('dynamodb')
sns = session_boto.client('sns')

users_table = dynamodb.Table(DYNAMODB_USERS_TABLE)
events_table = dynamodb.Table(DYNAMODB_EVENTS_TABLE)
tickets_table = dynamodb.Table(DYNAMODB_TICKETS_TABLE)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = str(uuid.uuid4())
        name = request.form['name']
        email = request.form['email']
        role = request.form['role']
        password = hash_password(request.form['password'])

        users_table.put_item(Item={
            'user_id': user_id,
            'name': name,
            'email': email,
            'role': role,
            'password': password
        })
        flash("Registration successful.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        role = request.form['role']
        password = hash_password(request.form['password'])

        response = users_table.scan(
            FilterExpression="#e = :e AND #r = :r",
            ExpressionAttributeNames={"#e": "email", "#r": "role"},
            ExpressionAttributeValues={":e": email, ":r": role}
        )

        if response['Items']:
            user = response['Items'][0]
            if user.get('password') == password:
                session['email'] = user['email']
                session['role'] = user['role']
                session['name'] = user['name']
                session['user_id'] = user['user_id']
            
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password.")
        else:
            flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))

    role = session['role']
    if role == 'attendee':
        events = events_table.scan()['Items']
    elif role == 'organizer':
        events = events_table.scan(
            FilterExpression="organizer_email = :e",
            ExpressionAttributeValues={":e": session['email']}
        )['Items']
    elif role == 'admin':
        stats = {'total_events': len(events_table.scan()['Items'])}
        return render_template('admin_dashboard.html', stats=stats)
    else:
        events = []

    return render_template('dashboard.html', events=events)

@app.route('/create-event', methods=['GET', 'POST'])
def create_event():
    if session.get('role') != 'organizer':
        return redirect(url_for('login'))

    if request.method == 'POST':
        event_id = str(uuid.uuid4())
        title = request.form['title']
        description = request.form['description']
        total_tickets = int(request.form['total_tickets'])
        date = request.form['date']
        ticket_cost = Decimal(request.form['ticket_cost'])

        events_table.put_item(Item={
            'event_id': event_id,
            'organizer_email': session['email'],
            'title': title,
            'description': description,
            'total_tickets': total_tickets,
            'available_tickets': total_tickets,
            'date': date,
            'ticket_cost': ticket_cost
        })
        flash("Event created.")
        return redirect(url_for('dashboard'))

    return render_template('create_event.html')

@app.route('/book/<event_id>')
def book(event_id):
    if session.get('role') != 'attendee':
        return redirect(url_for('login'))

    event = events_table.get_item(Key={'event_id': event_id}).get('Item')
    if event and int(event['available_tickets']) > 0:
        ticket_id = str(uuid.uuid4())

        events_table.update_item(
            Key={'event_id': event_id},
            UpdateExpression="SET available_tickets = available_tickets - :val",
            ExpressionAttributeValues={':val': 1}
        )

        tickets_table.put_item(Item={
            'ticket_id': ticket_id,
            'user_email': session['email'],
            'event_id': event_id,
            'status': 'booked'
        })

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=f"Ticket booked for event: {event['title']}",
            Subject="Ticket Confirmation"
        )

        return render_template('ticket_confirmation.html', event_title=event['title'])
    else:
        flash("Tickets sold out or event not found.")
        return redirect(url_for('dashboard'))

@app.route('/attendee/bookings')
def attendee_bookings():
    if session.get('role') != 'attendee':
        return redirect(url_for('login'))

    email = session['email']
    
    bookings = tickets_table.scan(
        FilterExpression="user_email = :e",
        ExpressionAttributeValues={":e": email}
    )['Items']
    
    bookings_with_event_details = []
    for booking in bookings:
        event = events_table.get_item(Key={'event_id': booking.get('event_id')}).get('Item')
        if event:
            bookings_with_event_details.append({
                'event_title': event.get('title', 'Untitled Event'),
                'event_date': event.get('date', 'Date Not Available'),
                'status': booking.get('status', 'Unknown')
            })

    return render_template('my_bookings.html', bookings=bookings_with_event_details)

@app.route('/attendee/account', methods=['GET', 'POST'])
def attendee_account():
    if session.get('role') != 'attendee':
        return redirect(url_for('login'))

    if request.method == 'POST':
        users_table.delete_item(Key={'user_id': session['user_id']})
        session.clear()
        flash("Account deleted successfully.")
        return redirect(url_for('index'))

    return render_template('attendee_account.html', name=session['name'], email=session['email'])

@app.route('/organizer/stats')
def organizer_stats():
    if session.get('role') != 'organizer':
        return redirect(url_for('login'))
    
    email = session['email']
    search_query = request.args.get('search', '')  

    events = events_table.scan(
        FilterExpression="organizer_email = :e AND contains(title, :search_query)",
        ExpressionAttributeValues={":e": email, ":search_query": search_query}
    )['Items']

    stats = []
    total_revenue = 0
    total_tickets_sold = 0

    for event in events:
        event_id = event['event_id']
        ticket_price = float(event['ticket_cost'])
        total = int(event['total_tickets'])
        available = int(event['available_tickets'])
        sold = total - available
        revenue = sold * ticket_price

        total_revenue += revenue
        total_tickets_sold += sold

        stats.append({
            'title': event['title'],
            'date': event['date'],
            'ticket_price': ticket_price,
            'sold': sold,
            'total': total,
            'revenue': revenue
        })

    return render_template('stats.html', stats=stats, total_revenue=total_revenue, total_tickets_sold=total_tickets_sold)

@app.route('/organizer/account', methods=['GET', 'POST'])
def organizer_account():
    if session.get('role') != 'organizer':
        return redirect(url_for('login'))

    if request.method == 'POST':
        users_table.delete_item(Key={'user_id': session['user_id']})
        session.clear()
        flash("Account deleted successfully.")
        return redirect(url_for('index'))

    return render_template('account.html', name=session['name'], email=session['email'])

@app.route('/admin/manage-events')
def manage_events():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    events = events_table.scan()['Items']
    return render_template('manage_events.html', events=events)

@app.route('/admin/manage-users')
def manage_users():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    users = users_table.scan()['Items']
    return render_template('manage_users.html', users=users)

@app.route('/delete-event/<event_id>', methods=['POST'])
def delete_event(event_id):
    if session.get('role') == 'admin':
        events_table.delete_item(Key={'event_id': event_id})
        flash("Event deleted.")
    return redirect(url_for('manage_events'))

@app.route('/delete-user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') == 'admin':
        users_table.delete_item(Key={'user_id': user_id})
        flash("User deleted.")
    return redirect(url_for('manage_users'))

@app.route('/edit_event/<event_id>', methods=['GET', 'POST'])
def edit_event(event_id):
    if 'email' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        updated_event = {
            'event_id': event_id,
            'title': request.form.get('title', ''),  # Default empty string if not present
            'description': request.form.get('description', ''),
            'organizer_email': request.form.get('organizer_email', ''),
            'total_tickets': int(request.form.get('total_tickets', 0)),  # Default to 0 if not present
            'available_tickets': int(request.form.get('available_tickets', 0)),  # Default to 0 if not present
            'date': request.form.get('date', ''),
            'ticket_cost': Decimal(request.form.get('ticket_cost', 0.0)),  # Default to 0.0 if not present
        }

        # Update the event in the database
        events_table.put_item(Item=updated_event)
        flash('Event updated successfully!', 'success')
        return redirect(url_for('manage_events'))

    # Fetch the current event details from the database
    response = events_table.get_item(Key={'event_id': event_id})
    event = response.get('Item')

    if not event:
        flash("Event not found.")
        return redirect(url_for('manage_events'))

    return render_template('edit_event.html', event=event)


@app.route('/admin/stats')
def admin_stats():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    total_events = events_table.scan()['Count']
    total_users = users_table.scan()['Count']

    tickets_sold = tickets_table.scan(
        FilterExpression="#s = :status",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": "booked"}
    )['Count']

    total_revenue = 0
    all_events = events_table.scan()['Items']
    for event in all_events:
        ticket_price = float(event['ticket_cost'])
        total_tickets = int(event['total_tickets'])
        available_tickets = int(event['available_tickets'])
        sold_tickets = total_tickets - available_tickets
        revenue = sold_tickets * ticket_price
        total_revenue += revenue

    stats = {
        'total_events': total_events,
        'total_users': total_users,
        'tickets_sold': tickets_sold,
        'total_revenue': total_revenue
    }

    return render_template('admin_dashboard.html', stats=stats)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Auto-fix events missing 'available_tickets' on startup
def fix_missing_available_tickets():
    events = events_table.scan()['Items']
    for event in events:
        if 'available_tickets' not in event:
            events_table.update_item(
                Key={'event_id': event['event_id']},
                UpdateExpression='SET available_tickets = :val',
                ExpressionAttributeValues={':val': int(event['total_tickets'])}
            )
            print(f"Fixed event: {event['event_id']}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
