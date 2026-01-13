from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_cors import CORS
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
import requests
import json
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta

# Import database and models
from models import db, User, Host, Command

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
# Use absolute path for database to ensure it's created in the correct location
db_path = os.getenv('DATABASE_URI')
if not db_path:
    # Create absolute path to data directory
    base_dir = os.path.abspath(os.path.dirname(__file__))
    data_dir = os.path.join(base_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    db_path = f'sqlite:///{os.path.join(data_dir, "neonc2.db")}'
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)

# Initialize database
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(str(user_id))


def middleware_auth(func):
    """Middleware decorator to check if user is authenticated."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler."""
    if current_user.is_authenticated:
        return redirect(url_for('console'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        if not username or not password:
            flash('Please provide both username and password.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('hosts'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if current_user.is_authenticated:
        return redirect(url_for('hosts'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        email = request.form.get('email')
        
        # Validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if password != password_confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if email and User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email if email else None)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration.', 'error')
    
    return render_template('register.html')


@app.route('/hosts')
@middleware_auth
def hosts():
    """List all registered hosts."""
    # Check for idle hosts and increment missed cycles
    check_idle_hosts()
    
    hosts_list = Host.query.order_by(Host.last_seen.desc()).all()
    # Calculate missed cycles for each host (time-based)
    for host in hosts_list:
        host.missed_cycles = calculate_missed_cycles(host)
    return render_template('hosts.html', hosts=hosts_list)


@app.route('/hosts/register', methods=['GET', 'POST'])
@middleware_auth
def register_host():
    """Manual host registration page."""
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        ip_address = request.form.get('ip_address')
        os_type = request.form.get('os_type', 'unknown')
        os_version = request.form.get('os_version', '')
        architecture = request.form.get('architecture', '')
        
        if not hostname or not ip_address:
            flash('Hostname and IP address are required.', 'error')
            return render_template('register_host.html')
        
        # Check if host already exists by IP
        existing_host = Host.query.filter_by(ip_address=ip_address).first()
        if existing_host:
            flash(f'Host with IP {ip_address} already exists.', 'error')
            return render_template('register_host.html')
        
        # Create host metadata
        host_metadata = {}
        if architecture:
            host_metadata['architecture'] = architecture
        
        host = Host(
            hostname=hostname,
            ip_address=ip_address,
            os_type=os_type,
            os_version=os_version,
            hardware_id=None,  # Manual registration doesn't have hardware ID
            idle_timeout_cycles=5,  # Default 5 cycles
            sync_frequency=5,  # Default 5 seconds
            host_metadata=json.dumps(host_metadata) if host_metadata else None,
            missed_cycles=0
        )
        
        try:
            db.session.add(host)
            db.session.commit()
            flash(f'Host {hostname} registered successfully!', 'success')
            return redirect(url_for('hosts'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error registering host: {str(e)}', 'error')
    
    return render_template('register_host.html')


@app.route('/api/hosts/<host_id>/deregister', methods=['DELETE'])
def api_deregister_host(host_id):
    """API endpoint for client to deregister itself."""
    host = Host.query.get(host_id)
    if not host:
        return json.dumps({'error': 'Host not found'}), 404, {'Content-Type': 'application/json'}
    
    hostname = host.hostname
    try:
        # Delete all commands for this host
        Command.query.filter_by(host_id=host_id).delete()
        # Delete the host
        db.session.delete(host)
        db.session.commit()
        return json.dumps({'success': True, 'message': f'Host {hostname} deregistered'}), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        db.session.rollback()
        return json.dumps({'error': f'Error deregistering host: {str(e)}'}), 500, {'Content-Type': 'application/json'}


@app.route('/hosts/<host_id>/delete', methods=['POST'])
@middleware_auth
def delete_host(host_id):
    """Delete a host."""
    host = Host.query.get(host_id)
    if not host:
        flash('Host not found.', 'error')
        return redirect(url_for('hosts'))
    
    hostname = host.hostname
    try:
        # Delete all commands for this host first
        Command.query.filter_by(host_id=host_id).delete()
        db.session.delete(host)
        db.session.commit()
        flash(f'Host {hostname} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting host: {str(e)}', 'error')
    
    return redirect(url_for('hosts'))


def check_idle_hosts():
    """Check for idle hosts and mark them as idle after missing configured cycles.
    Uses time-based calculation instead of incrementing counters."""
    try:
        active_hosts = Host.query.filter(
            Host.is_active == True,
            Host.is_idle == False
        ).all()
        
        marked_idle_count = 0
        now = datetime.utcnow()
        
        for host in active_hosts:
            # Get sync frequency for this host (default 5 seconds)
            sync_interval = host.sync_frequency if host.sync_frequency else 5
            idle_timeout = host.idle_timeout_cycles if host.idle_timeout_cycles else 5
            
            if host.last_seen:
                # Calculate how many sync cycles have been missed based on actual time elapsed
                # This is time-based and not affected by page reloads
                time_since_last_seen = (now - host.last_seen).total_seconds()
                missed_cycles = int(time_since_last_seen / sync_interval)
                
                # Update missed_cycles in database (for display purposes, but calculation is always time-based)
                host.missed_cycles = max(0, missed_cycles)
                
                # Mark as idle if it has missed the configured number of cycles
                if missed_cycles >= idle_timeout:
                    host.is_idle = True
                    host.is_active = False # Mark as inactive (but not delete)
                    log_message = f"Host {host.hostname} ({host.ip_address}) marked as idle after {missed_cycles} missed cycles"
                    print(log_message)
                    marked_idle_count += 1
            else:
                # If last_seen is None, treat as never seen
                host.missed_cycles = 0

        if marked_idle_count > 0:
            print(f"Marked {marked_idle_count} host(s) as idle")

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error checking idle hosts: {e}")


def calculate_missed_cycles(host):
    """Calculate missed cycles for a host based on current time.
    This is a pure calculation function that doesn't modify the database."""
    if not host.last_seen:
        return 0
    
    sync_interval = host.sync_frequency if host.sync_frequency else 5
    now = datetime.utcnow()
    time_since_last_seen = (now - host.last_seen).total_seconds()
    missed_cycles = int(time_since_last_seen / sync_interval)
    return max(0, missed_cycles)


@app.route('/api/hosts/<host_id>/commands', methods=['POST'])
@middleware_auth
def api_create_command(host_id):
    """API endpoint to create a new command for a host."""
    host = Host.query.get(host_id)
    if not host:
        return json.dumps({'error': 'Host not found'}), 404, {'Content-Type': 'application/json'}
    
    data = request.get_json()
    if not data or 'command' not in data:
        return json.dumps({'error': 'command is required'}), 400, {'Content-Type': 'application/json'}
    
    cmd_str = data['command']
    
    # Handle special server commands
    if cmd_str.startswith('/'):
        if cmd_str == '/deregister':
            # Create a command record so client receives it
            command = Command(
                host_id=host_id,
                command=cmd_str,
                status='pending'
            )
            db.session.add(command)
            db.session.commit()
            return json.dumps({
                'success': True,
                'message': 'Deregister command queued. Client will delete entry and exit.',
                'command': command.to_dict()
            }), 201, {'Content-Type': 'application/json'}
        elif cmd_str == '/delete':
            # Create a command record so client receives it
            command = Command(
                host_id=host_id,
                command=cmd_str,
                status='pending'
            )
            db.session.add(command)
            db.session.commit()
            return json.dumps({
                'success': True,
                'message': 'Delete command queued. Client will deregister, delete executable, and exit.',
                'command': command.to_dict()
            }), 201, {'Content-Type': 'application/json'}
        elif cmd_str.startswith('/set-idle-timeout'):
            # Parse: /set-idle-timeout 5
            try:
                parts = cmd_str.split()
                if len(parts) == 2:
                    cycles = int(parts[1])
                    if 1 <= cycles <= 100:
                        host.idle_timeout_cycles = cycles
                        db.session.commit()
                        # Create a command record for the response
                        command = Command(
                            host_id=host_id,
                            command=cmd_str,
                            status='completed',
                            result=f'Idle timeout set to {cycles} cycles',
                            completed_at=datetime.utcnow()
                        )
                        db.session.add(command)
                        db.session.commit()
                        return json.dumps({
                            'success': True,
                            'message': f'Idle timeout set to {cycles} cycles',
                            'command': command.to_dict()
                        }), 201, {'Content-Type': 'application/json'}
            except (ValueError, IndexError):
                pass
            return json.dumps({'error': 'Invalid format. Use: /set-idle-timeout <cycles> (1-100)'}), 400, {'Content-Type': 'application/json'}
        elif cmd_str.startswith('/set-sync-frequency'):
            # Parse: /set-sync-frequency 10
            try:
                parts = cmd_str.split()
                if len(parts) == 2:
                    seconds = int(parts[1])
                    if 1 <= seconds <= 300:
                        host.sync_frequency = seconds
                        db.session.commit()
                        # Create a command record for the response
                        command = Command(
                            host_id=host_id,
                            command=cmd_str,
                            status='completed',
                            result=f'Sync frequency set to {seconds} seconds',
                            completed_at=datetime.utcnow()
                        )
                        db.session.add(command)
                        db.session.commit()
                        return json.dumps({
                            'success': True,
                            'message': f'Sync frequency set to {seconds} seconds',
                            'command': command.to_dict()
                        }), 201, {'Content-Type': 'application/json'}
            except (ValueError, IndexError):
                pass
            return json.dumps({'error': 'Invalid format. Use: /set-sync-frequency <seconds> (1-300)'}), 400, {'Content-Type': 'application/json'}
    
    # Regular command
    command = Command(
        host_id=host_id,
        command=cmd_str,
        status='pending'
    )
    
    db.session.add(command)
    db.session.commit()
    return json.dumps({'success': True, 'command': command.to_dict()}), 201, {'Content-Type': 'application/json'}


@app.route('/console')
@app.route('/console/<host_id>')
@middleware_auth
def console(host_id=None):
    """Console page - requires authentication. Optionally for a specific host."""
    host = None
    commands = []
    if host_id:
        host = Host.query.get(host_id)
        if not host:
            flash('Host not found.', 'error')
            return redirect(url_for('hosts'))
        # Get recent commands for this host
        commands = Command.query.filter_by(host_id=host_id).order_by(Command.created_at.desc()).limit(50).all()
    return render_template('console.html', host=host, commands=commands)


@app.route('/api/hosts', methods=['GET'])
@middleware_auth
def api_hosts():
    """API endpoint to get all hosts as JSON with real-time status."""
    # Check for idle hosts before returning
    check_idle_hosts()
    
    hosts_list = Host.query.order_by(Host.last_seen.desc()).all()
    hosts_data = []
    for host in hosts_list:
        host_dict = host.to_dict()
        # Calculate real-time missed cycles (time-based)
        host_dict['missed_cycles'] = calculate_missed_cycles(host)
        # Calculate time since last seen
        if host.last_seen:
            time_since = (datetime.utcnow() - host.last_seen).total_seconds()
            host_dict['seconds_since_last_seen'] = int(time_since)
        else:
            host_dict['seconds_since_last_seen'] = None
        hosts_data.append(host_dict)
    
    return json.dumps(hosts_data), 200, {'Content-Type': 'application/json'}


@app.route('/api/hosts/<host_id>/commands', methods=['GET'])
def api_get_commands(host_id):
    """API endpoint for clients to get pending commands."""
    host = Host.query.get(host_id)
    if not host:
        return json.dumps({'error': 'Host not found'}), 404, {'Content-Type': 'application/json'}
    
    # Update last_seen and reset missed cycles (host is active and back online)
    host.last_seen = datetime.utcnow()
    host.is_active = True
    host.is_idle = False  # Mark as no longer idle
    host.missed_cycles = 0  # Reset missed cycles on successful check-in
    
    # Update sync frequency if provided in request (for dynamic updates)
    # Note: This would require passing it in the request, but for now we'll use the stored value
    db.session.commit()
    
    # Get pending commands for this host
    pending_commands = Command.query.filter_by(
        host_id=host_id,
        status='pending'
    ).order_by(Command.created_at.asc()).limit(1).all()
    
    commands_data = [cmd.to_dict() for cmd in pending_commands]
    
    # Include host configuration in response so client can update its sync frequency
    response_data = {
        'commands': commands_data,
        'host_config': {
            'sync_frequency': host.sync_frequency or 5,
            'idle_timeout_cycles': host.idle_timeout_cycles or 5
        }
    }
    return json.dumps(response_data), 200, {'Content-Type': 'application/json'}


@app.route('/api/hosts/<host_id>/commands/<command_id>', methods=['GET'])
@middleware_auth
def api_get_command(host_id, command_id):
    """API endpoint to get a specific command and its result."""
    host = Host.query.get(host_id)
    if not host:
        return json.dumps({'error': 'Host not found'}), 404, {'Content-Type': 'application/json'}
    
    command = Command.query.filter_by(id=command_id, host_id=host_id).first()
    if not command:
        return json.dumps({'error': 'Command not found'}), 404, {'Content-Type': 'application/json'}
    
    return json.dumps({'success': True, 'command': command.to_dict()}), 200, {'Content-Type': 'application/json'}


@app.route('/api/hosts/<host_id>/commands/<command_id>/result', methods=['POST'])
def api_submit_result(host_id, command_id):
    """API endpoint for clients to submit command results."""
    host = Host.query.get(host_id)
    if not host:
        return json.dumps({'error': 'Host not found'}), 404, {'Content-Type': 'application/json'}
    
    command = Command.query.filter_by(id=command_id, host_id=host_id).first()
    if not command:
        return json.dumps({'error': 'Command not found'}), 404, {'Content-Type': 'application/json'}
    
    data = request.get_json()
    if not data:
        return json.dumps({'error': 'No data provided'}), 400, {'Content-Type': 'application/json'}
    
    # Update command with results
    command.status = data.get('status', 'completed')
    command.result = data.get('result')
    command.error = data.get('error')
    command.exit_code = data.get('exit_code')
    command.completed_at = datetime.utcnow()
    
    if command.status == 'executing':
        command.executed_at = datetime.utcnow()
    
    db.session.commit()
    
    return json.dumps({'success': True, 'command': command.to_dict()}), 200, {'Content-Type': 'application/json'}


@app.route('/api/hosts/<host_id>/commands/<command_id>/status', methods=['POST'])
def api_update_command_status(host_id, command_id):
    """API endpoint for clients to update command status (e.g., executing)."""
    host = Host.query.get(host_id)
    if not host:
        return json.dumps({'error': 'Host not found'}), 404, {'Content-Type': 'application/json'}
    
    command = Command.query.filter_by(id=command_id, host_id=host_id).first()
    if not command:
        return json.dumps({'error': 'Command not found'}), 404, {'Content-Type': 'application/json'}
    
    data = request.get_json()
    if not data:
        return json.dumps({'error': 'No data provided'}), 400, {'Content-Type': 'application/json'}
    
    status = data.get('status')
    if status:
        command.status = status
        if status == 'executing':
            command.executed_at = datetime.utcnow()
    
    db.session.commit()
    
    return json.dumps({'success': True, 'command': command.to_dict()}), 200, {'Content-Type': 'application/json'}


@app.route('/api/hosts', methods=['POST'])
def api_register_host():
    """API endpoint to register a new host. Matches by hardware_id first, then IP."""
    data = request.get_json()
    
    if not data:
        return json.dumps({'error': 'No data provided'}), 400, {'Content-Type': 'application/json'}
    
    hostname = data.get('hostname')
    ip_address = data.get('ip_address')
    hardware_id = data.get('hardware_id')
    
    if not hostname or not ip_address:
        return json.dumps({'error': 'hostname and ip_address are required'}), 400, {'Content-Type': 'application/json'}
    
    # Get client IP if not provided
    if ip_address == 'auto':
        ip_address = request.remote_addr
    
    # Try to match by hardware_id first (for reboots/reconnections)
    existing_host = None
    if hardware_id:
        existing_host = Host.query.filter_by(hardware_id=hardware_id).first()
    
    # If no match by hardware_id, try by IP
    if not existing_host:
        existing_host = Host.query.filter_by(ip_address=ip_address).first()
    
    if existing_host:
        # Update existing host (client came back online)
        existing_host.last_seen = datetime.utcnow()
        existing_host.hostname = hostname
        existing_host.ip_address = ip_address  # Update IP in case it changed
        existing_host.is_active = True
        existing_host.is_idle = False  # Mark as no longer idle
        existing_host.missed_cycles = 0  # Reset missed cycles
        
        # Update hardware_id if provided and not set
        if hardware_id and not existing_host.hardware_id:
            existing_host.hardware_id = hardware_id
        
        if 'os_type' in data:
            existing_host.os_type = data.get('os_type')
        if 'os_version' in data:
            existing_host.os_version = data.get('os_version')
        if 'architecture' in data:
            # Store architecture in metadata
            metadata = {}
            if existing_host.host_metadata:
                metadata = json.loads(existing_host.host_metadata)
            metadata['architecture'] = data.get('architecture')
            existing_host.host_metadata = json.dumps(metadata)
        if 'metadata' in data:
            # Merge with existing metadata
            existing_metadata = {}
            if existing_host.host_metadata:
                existing_metadata = json.loads(existing_host.host_metadata)
            existing_metadata.update(data.get('metadata', {}))
            existing_host.host_metadata = json.dumps(existing_metadata)
        db.session.commit()
        return json.dumps(existing_host.to_dict()), 200, {'Content-Type': 'application/json'}
    
    # Create new host
    host_metadata = {}
    if 'architecture' in data:
        host_metadata['architecture'] = data.get('architecture')
    if 'metadata' in data:
        host_metadata.update(data.get('metadata', {}))
    
    host = Host(
        hostname=hostname,
        ip_address=ip_address,
        os_type=data.get('os_type'),
        os_version=data.get('os_version'),
        hardware_id=hardware_id,
        idle_timeout_cycles=5,  # Default 5 cycles
        sync_frequency=5,  # Default 5 seconds
        host_metadata=json.dumps(host_metadata) if host_metadata else None
    )
    
    db.session.add(host)
    db.session.commit()
    return json.dumps(host.to_dict()), 201, {'Content-Type': 'application/json'}


@app.route('/api/download/<os_type>/<architecture>')
def api_download_client(os_type, architecture):
    """API endpoint to download client binary for specific OS/Architecture."""
    # Map OS/Arch to file names
    filename_map = {
        ('linux', 'amd64'): 'neonc2-client-linux-amd64',
        ('linux', 'arm64'): 'neonc2-client-linux-arm64',
        ('linux', '386'): 'neonc2-client-linux-386',
        ('windows', 'amd64'): 'neonc2-client-windows-amd64.exe',
        ('windows', '386'): 'neonc2-client-windows-386.exe',
        ('darwin', 'amd64'): 'neonc2-client-darwin-amd64',
        ('darwin', 'arm64'): 'neonc2-client-darwin-arm64',
    }
    
    filename = filename_map.get((os_type.lower(), architecture.lower()))
    if not filename:
        return json.dumps({'error': 'Unsupported OS/Architecture combination'}), 404, {'Content-Type': 'application/json'}
    
    # Get server URL from request
    server_url = request.host_url.rstrip('/')
    if request.is_secure:
        server_url = server_url.replace('http://', 'https://')
    else:
        # Use the request URL as-is
        server_url = request.url_root.rstrip('/')
    
    # Try to serve the file if it exists in the clients/build directory
    clients_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'clients', 'build')
    file_path = os.path.join(clients_dir, filename)
    
    # Always rebuild with embedded server URL to ensure it matches the current server
    # This ensures the client connects to the right server
    try:
        import subprocess
        clients_source_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'clients')
        main_file = os.path.join(clients_source_dir, 'main.go')
        
        # Build flags with embedded server URL
        ldflags = f'-s -w -X main.buildServerURL={server_url}'
        
        env = os.environ.copy()
        env['GOOS'] = os_type.lower()
        env['GOARCH'] = architecture.lower()
        
        result = subprocess.run(
            ['go', 'build', '-ldflags', ldflags, '-o', file_path, main_file],
            cwd=clients_source_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0:
            # If build fails, try to serve existing file if it exists
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True, download_name=filename)
            return json.dumps({
                'error': f'Failed to build client: {result.stderr}',
                'filename': filename
            }), 500, {'Content-Type': 'application/json'}
    except Exception as e:
        # If build fails, try to serve existing file if it exists
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=filename)
        return json.dumps({
            'error': f'Failed to build client: {str(e)}',
            'filename': filename
        }), 500, {'Content-Type': 'application/json'}
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename)
    
    # If file still doesn't exist, return error
    return json.dumps({
        'error': 'Binary not found and build failed',
        'filename': filename,
        'os': os_type,
        'architecture': architecture
    }), 404, {'Content-Type': 'application/json'}


@app.route('/')
def index():
    """Home page - redirects to hosts if authenticated, otherwise to login."""
    if current_user.is_authenticated:
        return redirect(url_for('hosts'))
    return redirect(url_for('login'))


def init_db():
    """Initialize database: run migrations."""
    with app.app_context():
        # Ensure data directory exists
        data_dir = os.path.join(os.getcwd(), 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Check if migrations directory exists
        migrations_dir = os.path.join(os.getcwd(), 'migrations')
        
        if os.path.exists(migrations_dir):
            # Run migrations to create/update database schema
            from flask_migrate import upgrade
            try:
                upgrade()
                print("Database migrations applied successfully.")
            except Exception as e:
                print(f"Error applying migrations: {e}")
                # Fallback to creating tables directly
                db.create_all()
        else:
            # If migrations haven't been initialized, create tables directly
            print("Migrations not initialized, creating tables directly...")
            db.create_all()
        
        # Admin user creation removed - users must register through the web interface


# Don't run init_db on import - only when explicitly running the app
# This prevents issues with Flask CLI commands
if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=8080)
