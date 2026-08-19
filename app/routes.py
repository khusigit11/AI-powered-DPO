from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app.models.database import (
    db, User, LoginAttempt, Incident, ActivityLog,
    ChecklistProgress, ROPARecord, ComplianceRecord,
    DPIARecord, SARRequest, Policy, TrainingRecord
)
from app.utils.detection import DetectionEngine

# single blueprint for the whole app - everyone gets the same pages
main_bp = Blueprint('main', __name__)

# this scans user inputs for suspicious stuff
detector = DetectionEngine()


# homepage, login, register, logout

@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr

        # keep a record of this attempt
        activity = ActivityLog(
            ip_address=ip_address,
            action='login_attempt',
            url='/login',
            method='POST',
            input_data=f'username={username}'
        )
        db.session.add(activity)

        # run the detection engine on what they typed
        for field_value in [username, password]:
            threats = detector.scan_all(field_value, source_ip=ip_address, target_url='/login')
            for threat in threats:
                detector.create_incident(threat, source_ip=ip_address, target_url='/login')
                activity.flagged = True
                flash('Suspicious input detected. This incident has been logged.', 'danger')

        user = User.query.filter_by(username=username).first()

        login_attempt = LoginAttempt(
            username=username,
            ip_address=ip_address,
            success=False,
            user_agent=request.headers.get('User-Agent', '')
        )

        if user and user.check_password(password):
            login_attempt.success = True
            db.session.add(login_attempt)
            db.session.commit()

            login_user(user)
            activity.user_id = user.id
            db.session.commit()

            # first time logging in? give them the 7 task checklist
            setup_checklist(user.id)

            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            db.session.add(login_attempt)
            db.session.commit()

            # too many wrong passwords? thats a brute-force attempt
            brute_result = detector.check_brute_force(username, ip_address)
            if brute_result['detected']:
                detector.create_incident(brute_result, source_ip=ip_address, target_url='/login')
                flash('Too many failed attempts. This has been logged as a security incident.', 'danger')
            else:
                flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr

        # making sure nobody is trying to inject something through registration
        for field_value in [username, email]:
            threats = detector.scan_all(field_value, source_ip=ip_address, target_url='/register')
            for threat in threats:
                detector.create_incident(threat, source_ip=ip_address, target_url='/register')
                flash('Suspicious input detected. This incident has been logged.', 'danger')
                return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # give them their checklist straight away
        setup_checklist(new_user.id)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')


@main_bp.route('/logout')
@login_required
def logout():
    activity = ActivityLog(
        user_id=current_user.id,
        ip_address=request.remote_addr,
        action='logout',
        url='/logout',
        method='GET'
    )
    db.session.add(activity)
    db.session.commit()

    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


# main pages

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # figure out how far along the user is with their dpo tasks
    total_tasks = 7
    completed_tasks = ChecklistProgress.query.filter_by(
        user_id=current_user.id, completed=True
    ).count()
    compliance_score = int((completed_tasks / total_tasks) * 100)

    # grab their checklist so we can show ticks and crosses
    checklist = ChecklistProgress.query.filter_by(
        user_id=current_user.id
    ).order_by(ChecklistProgress.task_number).all()

    # quick stats on incidents
    total_incidents = Incident.query.count()
    open_incidents = Incident.query.filter_by(status='open').count()
    recent_incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(5).all()

    return render_template('dashboard.html',
        completed_tasks=completed_tasks,
        total_tasks=total_tasks,
        compliance_score=compliance_score,
        checklist=checklist,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        recent_incidents=recent_incidents
    )


@main_bp.route('/dpo-hub')
@login_required
def dpo_hub():
    # this is where people learn what a dpo actually does
    return render_template('dpo_hub.html')


@main_bp.route('/checklist')
@login_required
def checklist():
    checklist = ChecklistProgress.query.filter_by(
        user_id=current_user.id
    ).order_by(ChecklistProgress.task_number).all()

    completed = sum(1 for task in checklist if task.completed)

    return render_template('checklist.html',
        checklist=checklist,
        completed=completed,
        total=7
    )


# the 7 dpo tasks - each one has its own page

@main_bp.route('/task/ropa', methods=['GET', 'POST'])
@login_required
def task_ropa():
    """task 1 - map your data - build a live inventory of personal data"""
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=1
    ).first()
    records = ROPARecord.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        action = request.form.get('action', '')

        # user is adding a new data entry to their inventory
        if action == 'add':
            record = ROPARecord(
                user_id=current_user.id,
                data_categories=request.form.get('data_type', ''),
                purpose=request.form.get('purpose', ''),
                lawful_basis=request.form.get('lawful_basis', ''),
                data_recipients=request.form.get('access', ''),
                retention_period=request.form.get('retention', ''),
                security_measures=request.form.get('security', '')
            )
            db.session.add(record)
            db.session.commit()
            flash('Data entry added to your inventory.', 'success')

        # user wants ai to analyse their whole inventory
        elif action == 'analyse':
            from app.utils.ai_api import ask_claude

            # build a summary of everything in their inventory
            inventory_text = ""
            for r in records:
                inventory_text += f"- Data: {r.data_categories}, Purpose: {r.purpose}, Lawful Basis: {r.lawful_basis}, Access: {r.data_recipients}, Retention: {r.retention_period}, Security: {r.security_measures}\n"

            prompt = f"""You are a Data Protection Officer reviewing an organisation's data inventory.

Here is their current data inventory:
{inventory_text}

Analyse this inventory and provide:
1. A brief summary of what data they hold
2. Any gaps or missing information you notice
3. Risk areas that need attention (high risk items)
4. Specific recommendations to improve their data protection
5. Whether any data types might need additional security measures

Keep it practical and actionable. Use plain English, no legal jargon."""

            ai_result = ask_claude(prompt)

            # mark task as complete since they have entries and ran analysis
            if task and not task.completed:
                task.completed = True
                task.completed_at = datetime.utcnow()
                task.ai_response = ai_result

            db.session.commit()
            flash('AI analysis complete. Task marked as done.', 'success')

            # reload records after changes
            records = ROPARecord.query.filter_by(user_id=current_user.id).all()
            return render_template('tasks/ropa.html', task=task, records=records, ai_analysis=ai_result)

        # user wants to delete an entry
                # user wants to delete an entry - also clears old analysis since data changed
        elif action == 'delete':
            record_id = request.form.get('record_id')
            record = ROPARecord.query.get(record_id)
            if record and record.user_id == current_user.id:
                db.session.delete(record)

                # check if inventory is now empty
                remaining = ROPARecord.query.filter_by(user_id=current_user.id).count()
                if remaining <= 1:  # this one is about to be deleted
                    # reset the task since there's no data left to analyse
                    if task:
                        task.completed = False
                        task.completed_at = None
                        task.ai_response = None

                db.session.commit()
                flash('Entry removed. Run AI Analyse again when your inventory is updated.', 'info')

        return redirect(url_for('main.task_ropa'))

    return render_template('tasks/ropa.html', task=task, records=records, ai_analysis=None)


@main_bp.route('/task/compliance', methods=['GET', 'POST'])
@login_required
def task_compliance():
    """task 2 - check your practices - form based compliance assessment"""
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=2
    ).first()
    records = ComplianceRecord.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        from app.utils.ai_api import ask_claude

        # grab the users answers to each compliance question
        data_minimisation = request.form.get('data_minimisation', '')
        lawful_basis_documented = request.form.get('lawful_basis_documented', '')
        consent_obtained = request.form.get('consent_obtained', '')
        data_accurate = request.form.get('data_accurate', '')
        retention_followed = request.form.get('retention_followed', '')
        security_measures = request.form.get('security_measures', '')
        breach_process_exists = request.form.get('breach_process_exists', '')
        dpo_appointed = request.form.get('dpo_appointed', '')

        # work out a basic score before ai gets involved
        answers = [data_minimisation, lawful_basis_documented, consent_obtained,
                   data_accurate, retention_followed, security_measures,
                   breach_process_exists, dpo_appointed]
        score = 0
        for a in answers:
            if a == 'yes':
                score += 100
            elif a == 'partial':
                score += 50
        compliance_score = int(score / len(answers))

        # ask ai to assess the results and give recommendations
        prompt = f"""You are a Data Protection Officer assessing an organisation's GDPR compliance.

Here are their answers to a compliance check:

1. Do you only collect data you actually need? {data_minimisation}
2. Is your legal reason for collecting data documented? {lawful_basis_documented}
3. Do you get proper consent where needed? {consent_obtained}
4. Is the personal data you hold accurate and up to date? {data_accurate}
5. Do you delete data when you no longer need it? {retention_followed}
6. Do you have security measures protecting personal data? {security_measures}
7. Do you have a process for handling data breaches? {breach_process_exists}
8. Has someone been assigned the DPO role? {dpo_appointed}

Their compliance score is {compliance_score}%.

Give them:
1. A brief overall assessment in 2-3 sentences
2. For each question they answered "no" or "partial" - explain why this is a problem and what they should do to fix it
3. If they scored above 80% - tell them what they are doing well

Keep it practical and in plain English. No legal jargon."""

        ai_result = ask_claude(prompt)

        # save the results
        record = ComplianceRecord(
            user_id=current_user.id,
            data_minimisation=data_minimisation,
            lawful_basis_documented=lawful_basis_documented,
            consent_obtained=consent_obtained,
            data_accurate=data_accurate,
            retention_followed=retention_followed,
            security_measures=security_measures,
            breach_process_exists=breach_process_exists,
            dpo_appointed=dpo_appointed,
            compliance_score=compliance_score,
            ai_assessment=ai_result
        )
        db.session.add(record)

        # mark task as complete
        if task:
            task.completed = True
            task.completed_at = datetime.utcnow()
            task.ai_response = ai_result

        db.session.commit()

        flash(f'Compliance check complete. Your score: {compliance_score}%', 'success')
        return redirect(url_for('main.task_compliance'))

    return render_template('tasks/compliance.html', task=task, records=records)


@main_bp.route('/task/dpia')
@login_required
def task_dpia():
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=3
    ).first()
    records = DPIARecord.query.filter_by(user_id=current_user.id).all()
    return render_template('tasks/dpia.html', task=task, records=records)


@main_bp.route('/task/sar')
@login_required
def task_sar():
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=4
    ).first()
    records = SARRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('tasks/sar.html', task=task, records=records)


@main_bp.route('/task/breach')
@login_required
def task_breach():
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=5
    ).first()
    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    return render_template('tasks/breach.html', task=task, incidents=incidents)


@main_bp.route('/task/policy')
@login_required
def task_policy():
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=6
    ).first()
    policies = Policy.query.filter_by(user_id=current_user.id).all()
    return render_template('tasks/policy.html', task=task, policies=policies)


@main_bp.route('/task/training')
@login_required
def task_training():
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=7
    ).first()
    records = TrainingRecord.query.filter_by(user_id=current_user.id).all()
    return render_template('tasks/training.html', task=task, records=records)


# breach monitoring pages

@main_bp.route('/incidents')
@login_required
def incidents():
    all_incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    return render_template('monitor/incidents.html', incidents=all_incidents)


@main_bp.route('/incident/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    return render_template('monitor/incident_detail.html', incident=incident)


@main_bp.route('/login-monitor')
@login_required
def login_monitor():
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('monitor/login_attempts.html', attempts=attempts)


@main_bp.route('/activity')
@login_required
def activity():
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
    return render_template('monitor/activity_log.html', activities=activities)


@main_bp.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    results = []
    if request.method == 'POST':
        query = request.form.get('query', '')
        ip_address = request.remote_addr

        activity = ActivityLog(
            user_id=current_user.id,
            ip_address=ip_address,
            action='search',
            url='/search',
            method='POST',
            input_data=query
        )
        db.session.add(activity)

        threats = detector.scan_all(query, source_ip=ip_address, target_url='/search')

        if threats:
            for threat in threats:
                detector.create_incident(threat, source_ip=ip_address, target_url='/search')
                activity.flagged = True
            db.session.commit()
            flash('Warning: Suspicious input detected. This incident has been logged.', 'danger')
        else:
            results = [f'Search result for: {query}']
            flash('Search completed.', 'success')

        db.session.commit()

    return render_template('search.html', results=results)


@main_bp.route('/submit-url', methods=['GET', 'POST'])
@login_required
def submit_url():
    if request.method == 'POST':
        url_input = request.form.get('url', '')
        ip_address = request.remote_addr

        activity = ActivityLog(
            user_id=current_user.id,
            ip_address=ip_address,
            action='url_submission',
            url='/submit-url',
            method='POST',
            input_data=url_input
        )
        db.session.add(activity)

        threats = detector.scan_all(url_input, source_ip=ip_address, target_url='/submit-url')

        if threats:
            for threat in threats:
                detector.create_incident(threat, source_ip=ip_address, target_url='/submit-url')
                activity.flagged = True
            db.session.commit()
            flash('Warning: This URL has been flagged as suspicious. Incident logged.', 'danger')
        else:
            flash('URL submitted successfully. No threats detected.', 'success')

        db.session.commit()

    return render_template('submit_url.html')


# this runs once when a user first signs up or logs in
# it gives them the 7 dpo tasks they need to work through
def setup_checklist(user_id):
    already_done = ChecklistProgress.query.filter_by(user_id=user_id).first()
    if already_done:
        return

    tasks = [
        (1, 'Know Your Data (ROPA)'),
        (2, 'Check Compliance'),
        (3, 'Assess Risks (DPIA)'),
        (4, 'Handle Requests (SAR)'),
        (5, 'Detect Breaches'),
        (6, 'Review Policies'),
        (7, 'Train Staff'),
    ]

    for number, name in tasks:
        task = ChecklistProgress(
            user_id=user_id,
            task_number=number,
            task_name=name,
            completed=False
        )
        db.session.add(task)

    db.session.commit()