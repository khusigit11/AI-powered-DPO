from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file
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

        # user wants ai to analyse selected entries from their inventory
        elif action == 'analyse':
            from app.utils.ai_api import ask_claude

            selected_ids = request.form.getlist('selected_records')

            # if specific entries selected use those, otherwise analyse everything
            if selected_ids:
                selected_records = ROPARecord.query.filter(
                    ROPARecord.id.in_(selected_ids),
                    ROPARecord.user_id == current_user.id
                ).all()
            else:
                selected_records = records

            if not selected_records:
                flash('No entries to analyse.', 'warning')
                return redirect(url_for('main.task_ropa'))

            # build a summary of the selected entries
            inventory_text = ""
            for r in selected_records:
                inventory_text += f"- Data: {r.data_categories}, Purpose: {r.purpose}, Lawful Basis: {r.lawful_basis}, Access: {r.data_recipients}, Retention: {r.retention_period}, Security: {r.security_measures}\n"

            prompt = f"""You are a Data Protection Officer reviewing an organisation's data inventory.

Here are the selected data entries to analyse ({len(selected_records)} items):
{inventory_text}

Analyse these entries and provide:
1. A brief summary of what data is held
2. Any gaps or missing information you notice
3. Risk areas that need attention (high risk items)
4. Specific recommendations to improve data protection
5. Whether any data types need additional security measures

Keep it practical and actionable. Use plain English."""

            ai_result = ask_claude(prompt)

            # mark task as complete
            if task and not task.completed:
                task.completed = True
                task.completed_at = datetime.utcnow()
                task.ai_response = ai_result

            db.session.commit()
            flash(f'AI analysis complete for {len(selected_records)} entries. Task marked as done.', 'success')

            records = ROPARecord.query.filter_by(user_id=current_user.id).all()
            return render_template('tasks/ropa.html', task=task, records=records, ai_analysis=ai_result)

        # user wants to delete an entry
        elif action == 'delete':
            record_id = request.form.get('record_id')
            record = ROPARecord.query.get(record_id)
            if record and record.user_id == current_user.id:
                db.session.delete(record)

                # check if inventory is now empty
                remaining = ROPARecord.query.filter_by(user_id=current_user.id).count()
                if remaining <= 1:
                    if task:
                        task.completed = False
                        task.completed_at = None
                        task.ai_response = None

                db.session.commit()
                flash('Entry removed. Run AI Analyse again when your inventory is updated.', 'info')

                # bulk delete selected entries
        elif action == 'bulk_delete':
            record_ids = request.form.getlist('record_ids')
            if record_ids:
                count = 0
                for rid in record_ids:
                    record = ROPARecord.query.get(rid)
                    if record and record.user_id == current_user.id:
                        db.session.delete(record)
                        count += 1

                # if all entries deleted, reset the task
                remaining = ROPARecord.query.filter_by(user_id=current_user.id).count()
                if remaining <= count:
                    if task:
                        task.completed = False
                        task.completed_at = None
                        task.ai_response = None

                db.session.commit()
                flash(f'{count} entries removed.', 'info')

        # ai generates a starter inventory based on organisation type
        elif action == 'generate':
            from app.utils.ai_api import ask_claude
            org_type = request.form.get('org_type', '')

            prompt = f"""You are helping a {org_type} organisation create their data inventory.

Generate exactly 6 common types of personal data that a typical {org_type} would collect and process.

For each one, respond in this EXACT format (one per line, fields separated by |):
DATA_TYPE | PURPOSE | LAWFUL_BASIS | ACCESS | RETENTION | SECURITY

Rules:
- DATA_TYPE: the type of personal data (e.g. Customer email addresses)
- PURPOSE: why they collect it (e.g. Send order confirmations)
- LAWFUL_BASIS: must be one of: Consent, Contract, Legal Obligation, Legitimate Interest
- ACCESS: who can see it (e.g. Sales team, HR department)
- RETENTION: must be one of: Less than 1 year, 1-2 years, 3-5 years, 6-10 years, As long as they are a customer
- SECURITY: must be one of: Password protected system, Encrypted and password protected, Restricted access - only certain staff, Cloud storage with login required

Give exactly 6 lines. No headers. No numbering. No extra text. Just 6 lines in the format above."""

            ai_result = ask_claude(prompt)

            # parse the ai response into records
            count = 0
            for line in ai_result.strip().split('\n'):
                parts = [p.strip() for p in line.split('|')]
                if len(parts) == 6:
                    record = ROPARecord(
                        user_id=current_user.id,
                        data_categories=parts[0],
                        purpose=parts[1],
                        lawful_basis=parts[2],
                        data_recipients=parts[3],
                        retention_period=parts[4],
                        security_measures=parts[5]
                    )
                    db.session.add(record)
                    count += 1

            db.session.commit()
            if count > 0:
                flash(f'AI generated {count} data entries for a {org_type}. Review and edit as needed.', 'success')
            else:
                flash('Could not generate entries. Try again.', 'warning')

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


@main_bp.route('/task/dpia', methods=['GET', 'POST'])
@login_required
def task_dpia():
    """task 3 - assess risks using guided selectors + ai"""
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=3
    ).first()
    records = DPIARecord.query.filter_by(user_id=current_user.id).order_by(DPIARecord.created_at.desc()).all()

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'assess':
            from app.utils.ai_api import ask_claude

            project_name = request.form.get('project_name', '')
            project_type = request.form.get('project_type', '')
            data_types = request.form.getlist('data_types')
            scale = request.form.get('scale', '')
            third_party = request.form.get('third_party', '')
            data_abroad = request.form.get('data_abroad', '')
            extra_info = request.form.get('extra_info', '')

            # calculate preliminary risk score based on selections
            risk_score = 0
            high_risk_data = ['Health data', 'Biometric data', "Children's data", 'Criminal records']
            medium_risk_data = ['Payment details', 'Location data', 'Photos or videos', 'Browsing or online activity']

            for dt in data_types:
                if dt in high_risk_data:
                    risk_score += 4
                elif dt in medium_risk_data:
                    risk_score += 3
                else:
                    risk_score += 1

            if scale == '10,000+':
                risk_score += 3
            elif scale == '1,000 - 10,000':
                risk_score += 2
            elif scale == '100 - 1,000':
                risk_score += 1

            if third_party == 'Yes':
                risk_score += 2
            if data_abroad == 'Yes':
                risk_score += 2

            # cap at 10
            risk_score = min(risk_score, 10)

            # determine risk level
            if risk_score >= 7:
                risk_level = 'High'
            elif risk_score >= 4:
                risk_level = 'Medium'
            else:
                risk_level = 'Low'

            data_types_str = ', '.join(data_types) if data_types else 'Not specified'
            individuals = scale or 'Not specified'

            # build description from selections
            description = f"Project type: {project_type}. Data collected: {data_types_str}. Scale: {scale}. Third party sharing: {third_party}. Data leaves UK: {data_abroad}."
            if extra_info:
                description += f" Additional context: {extra_info}"

            # ask ai for full assessment
            prompt = f"""You are a Data Protection Officer conducting a risk assessment on a proposed project.

Project: {project_name}
Type: {project_type}
Personal data to be collected: {data_types_str}
Number of people affected: {scale}
Data shared with third parties: {third_party}
Data transferred outside the UK: {data_abroad}
Additional context: {extra_info if extra_info else 'None provided'}

Preliminary risk score: {risk_score}/10 ({risk_level} risk)

Based on this information, provide a detailed risk assessment:

1. OVERALL RISK LEVEL: Confirm or adjust the preliminary {risk_level} risk rating and explain why
2. TOP RISKS: List the 3-5 most important data protection risks specific to this project
3. IMPACT ON INDIVIDUALS: What could happen to affected people if something went wrong
4. SAFEGUARDS REQUIRED: For each risk identified, recommend a specific safeguard or control
5. DECISION: Should this project proceed as planned, proceed with modifications, or be stopped until risks are addressed
6. STAKEHOLDER ACTIONS: What should the DPO tell management, staff, and affected individuals about this project

Be specific to this project. No generic advice. Plain English."""

            ai_result = ask_claude(prompt)

            # check if ai adjusted the risk level
            ai_lower = ai_result.lower()
            if 'high risk' in ai_lower or 'high-risk' in ai_lower:
                risk_level = 'High'
            elif 'low risk' in ai_lower or 'low-risk' in ai_lower:
                risk_level = 'Low'

            record = DPIARecord(
                user_id=current_user.id,
                project_name=project_name,
                project_description=description,
                data_involved=data_types_str,
                individuals_affected=individuals,
                risk_level=risk_level,
                ai_assessment=ai_result,
                recommendations=f"Preliminary score: {risk_score}/10"
            )
            db.session.add(record)

            if task and not task.completed:
                task.completed = True
                task.completed_at = datetime.utcnow()
                task.ai_response = ai_result

            db.session.commit()
            flash(f'Risk assessment complete. Risk level: {risk_level} ({risk_score}/10).', 'success')

        elif action == 'delete':
            record_id = request.form.get('record_id')
            record = DPIARecord.query.get(record_id)
            if record and record.user_id == current_user.id:
                db.session.delete(record)
                db.session.commit()
                flash('Assessment removed.', 'info')

        return redirect(url_for('main.task_dpia'))

    return render_template('tasks/dpia.html', task=task, records=records)

@main_bp.route('/task/sar', methods=['GET', 'POST'])
@login_required
def task_sar():
    """task 4 - handle data requests with 30 day countdown"""
    from datetime import timedelta

    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=4
    ).first()
    requests_list = SARRequest.query.filter_by(user_id=current_user.id).order_by(SARRequest.created_at.desc()).all()

    # calculate days remaining for each request
    for req in requests_list:
        if req.deadline:
            remaining = (req.deadline - datetime.utcnow()).days
            req.days_remaining = max(remaining, 0)
        else:
            req.days_remaining = 0

    if request.method == 'POST':
        action = request.form.get('action', '')

        # log a new data request
        if action == 'add':
            requester_name = request.form.get('requester_name', '')
            requester_email = request.form.get('requester_email', '')
            request_type = request.form.get('request_type', '')
            request_details = request.form.get('request_details', '')

            # 30 day deadline from today
            deadline = datetime.utcnow() + timedelta(days=30)

            new_request = SARRequest(
                user_id=current_user.id,
                requester_name=requester_name,
                requester_email=requester_email,
                request_type=request_type,
                request_details=request_details,
                deadline=deadline,
                status='pending'
            )
            db.session.add(new_request)
            db.session.commit()
            flash(f'Request logged. Deadline: {deadline.strftime("%d/%m/%Y")} (30 days).', 'success')

        # ai drafts a response
        elif action == 'draft_response':
            from app.utils.ai_api import ask_claude

            request_id = request.form.get('request_id')
            sar = SARRequest.query.get(request_id)

            if sar and sar.user_id == current_user.id:
                prompt = f"""You are a Data Protection Officer drafting a formal response to a data subject request.

Request details:
- From: {sar.requester_name} ({sar.requester_email})
- Request type: {sar.request_type}
- What they asked: {sar.request_details}
- Date received: {sar.created_at.strftime('%d/%m/%Y')}
- Deadline: {sar.deadline.strftime('%d/%m/%Y')}

Draft a professional response letter that:
1. Acknowledges the request
2. Confirms what action will be taken
3. Explains the timeline
4. Is written in plain English — not legal language
5. Is ready to send to the person

Also provide:
- A brief note to the DPO on what internal steps need to happen to fulfil this request
- Any risks or considerations the DPO should be aware of"""

                ai_result = ask_claude(prompt)

                sar.ai_response = ai_result
                db.session.commit()
                flash('AI has drafted a response.', 'success')

        # mark request as complete
        elif action == 'complete':
            request_id = request.form.get('request_id')
            sar = SARRequest.query.get(request_id)
            if sar and sar.user_id == current_user.id:
                sar.status = 'completed'
                sar.completed_at = datetime.utcnow()

                # mark task as complete after handling at least one request
                if task and not task.completed:
                    task.completed = True
                    task.completed_at = datetime.utcnow()

                db.session.commit()
                flash('Request marked as completed.', 'success')

        # reopen a completed request
        elif action == 'reopen':
            request_id = request.form.get('request_id')
            sar = SARRequest.query.get(request_id)
            if sar and sar.user_id == current_user.id:
                sar.status = 'pending'
                sar.completed_at = None
                db.session.commit()
                flash('Request reopened.', 'info')

        # delete a request
        elif action == 'delete':
            request_id = request.form.get('request_id')
            sar = SARRequest.query.get(request_id)
            if sar and sar.user_id == current_user.id:
                db.session.delete(sar)
                db.session.commit()
                flash('Request removed.', 'info')

                # simulate a realistic incoming request
        elif action == 'simulate':
            from app.utils.ai_api import ask_claude
            from datetime import timedelta

            prompt = """Generate a realistic data subject request from a fictional person. Respond in this EXACT format (fields separated by |):

NAME | EMAIL | TYPE | DETAILS

Rules:
- NAME: a realistic British name
- EMAIL: a realistic email address
- TYPE: must be one of: Access - see what data you hold, Deletion - remove all my data, Correction - fix incorrect data, Portability - give me a copy of my data, Objection - stop processing my data
- DETAILS: 1-2 sentences explaining what they specifically want, written as if the person is emailing the company

Give exactly 1 line. No extra text."""

            ai_result = ask_claude(prompt)

            parts = [p.strip() for p in ai_result.strip().split('|')]
            if len(parts) == 4:
                deadline = datetime.utcnow() + timedelta(days=30)
                new_request = SARRequest(
                    user_id=current_user.id,
                    requester_name=parts[0],
                    requester_email=parts[1],
                    request_type=parts[2],
                    request_details=parts[3],
                    deadline=deadline,
                    status='pending'
                )
                db.session.add(new_request)
                db.session.commit()
                flash(f'Simulated request from {parts[0]} received. 30-day countdown started.', 'success')
            else:
                flash('Could not generate a request. Try again.', 'warning')

        return redirect(url_for('main.task_sar'))

    # count stats
    pending_count = sum(1 for r in requests_list if r.status == 'pending')
    completed_count = sum(1 for r in requests_list if r.status == 'completed')
    urgent_count = sum(1 for r in requests_list if r.status == 'pending' and r.days_remaining <= 7)

    return render_template('tasks/sar.html', task=task, requests=requests_list,
        pending_count=pending_count, completed_count=completed_count, urgent_count=urgent_count)

@main_bp.route('/task/breach', methods=['GET', 'POST'])
@login_required
def task_breach():
    """task 5 - monitor threats and detect breaches"""
    task = ChecklistProgress.query.filter_by(
        user_id=current_user.id, task_number=5
    ).first()

    if request.method == 'POST':
        action = request.form.get('action', '')

        # user testing an attack via the test box
        if action == 'test_search':
            test_input = request.form.get('test_input', '')
            ip_address = request.remote_addr

            activity = ActivityLog(
                user_id=current_user.id,
                ip_address=ip_address,
                action='breach_test_search',
                url='/task/breach',
                method='POST',
                input_data=test_input
            )
            db.session.add(activity)

            threats = detector.scan_all(test_input, source_ip=ip_address, target_url='/task/breach')

            if threats:
                from app.utils.ai_api import ask_claude
                for threat in threats:
                    detector.create_incident(threat, source_ip=ip_address, target_url='/task/breach')
                    activity.flagged = True

                db.session.commit()

                # auto-classify new incidents with ai
                new_incidents = Incident.query.filter_by(severity=None).order_by(Incident.timestamp.desc()).all()
                for incident in new_incidents:
                    prompt = f"""Classify this security incident in 3 lines maximum:
- Threat: {incident.threat_type}
- Payload: {incident.payload}
- Target: {incident.target_url}

Line 1: Severity (CRITICAL, HIGH, MEDIUM, or LOW)
Line 2: Is this reportable to ICO? (Yes or No)
Line 3: One sentence recommendation for the DPO"""

                    ai_result = ask_claude(prompt)

                    severity = 'Medium'
                    severity_score = 0.5
                    is_reportable = False
                    ai_lower = ai_result.lower()
                    if 'critical' in ai_lower:
                        severity = 'Critical'
                        severity_score = 0.9
                        is_reportable = True
                    elif 'high' in ai_lower:
                        severity = 'High'
                        severity_score = 0.7
                        is_reportable = True
                    elif 'low' in ai_lower:
                        severity = 'Low'
                        severity_score = 0.3

                    incident.severity = severity
                    incident.severity_score = severity_score
                    incident.is_reportable = is_reportable
                    incident.recommendation = ai_result

                    if task and not task.completed:
                        task.completed = True
                        task.completed_at = datetime.utcnow()
                        task.ai_response = ai_result

                db.session.commit()
                flash(f'Threat detected and auto-classified! {len(threats)} incident(s) logged.', 'danger')
            else:
                db.session.commit()
                flash('No threats detected in that input.', 'success')

        # ai classifying an incident
        elif action == 'classify':
            from app.utils.ai_api import ask_claude
            incident_id = request.form.get('incident_id')
            incident = Incident.query.get(incident_id)

            if incident:
                prompt = f"""You are a Data Protection Officer assessing a security incident.

Incident details:
- Threat type: {incident.threat_type}
- Description: {incident.description}
- Source IP: {incident.source_ip}
- Target URL: {incident.target_url}
- Payload: {incident.payload}
- Timestamp: {incident.timestamp}

Assess this incident and provide:
1. Severity level: CRITICAL, HIGH, MEDIUM, or LOW
2. A severity score from 0.0 to 1.0
3. Whether this is reportable to the ICO under Article 33 (yes or no)
4. What data categories might be affected
5. Estimated number of people that could be affected
6. Likely consequences if this attack succeeded
7. Recommended actions the DPO should take right now

Format your response clearly with each point numbered. Use plain English."""

                ai_result = ask_claude(prompt)

                severity = 'Medium'
                severity_score = 0.5
                is_reportable = False

                ai_lower = ai_result.lower()
                if 'critical' in ai_lower:
                    severity = 'Critical'
                    severity_score = 0.9
                    is_reportable = True
                elif 'high' in ai_lower:
                    severity = 'High'
                    severity_score = 0.7
                    is_reportable = True
                elif 'low' in ai_lower:
                    severity = 'Low'
                    severity_score = 0.3
                    is_reportable = False

                incident.severity = severity
                incident.severity_score = severity_score
                incident.is_reportable = is_reportable
                incident.recommendation = ai_result

                if task and not task.completed:
                    task.completed = True
                    task.completed_at = datetime.utcnow()
                    task.ai_response = ai_result

                db.session.commit()
                flash(f'Incident classified as {severity}.', 'success')

        # deleting a single incident
        elif action == 'delete':
            incident_id = request.form.get('incident_id')
            incident = Incident.query.get(incident_id)
            if incident:
                db.session.delete(incident)
                db.session.commit()
                flash('Incident deleted.', 'info')

        # deleting all incidents
        elif action == 'delete_all':
            Incident.query.delete()
            db.session.commit()
            flash('All incidents cleared.', 'info')

        # marking an incident as resolved
        elif action == 'resolve':
            incident_id = request.form.get('incident_id')
            incident = Incident.query.get(incident_id)
            if incident:
                incident.status = 'resolved'
                db.session.commit()
                flash('Incident marked as resolved.', 'success')

        # reopen a resolved incident
        elif action == 'reopen':
            incident_id = request.form.get('incident_id')
            incident = Incident.query.get(incident_id)
            if incident:
                incident.status = 'open'
                db.session.commit()
                flash('Incident reopened.', 'info')

        return redirect(url_for('main.task_breach'))

    # handle filters from url params
    filter_type = request.args.get('filter', 'all')
    if filter_type == 'open':
        incidents = Incident.query.filter_by(status='open').order_by(Incident.timestamp.desc()).all()
    elif filter_type == 'resolved':
        incidents = Incident.query.filter_by(status='resolved').order_by(Incident.timestamp.desc()).all()
    elif filter_type == 'critical':
        incidents = Incident.query.filter(Incident.severity.in_(['Critical', 'High'])).order_by(Incident.timestamp.desc()).all()
    elif filter_type == 'unclassified':
        incidents = Incident.query.filter(Incident.severity.is_(None)).order_by(Incident.timestamp.desc()).all()
    else:
        incidents = Incident.query.order_by(Incident.timestamp.desc()).all()

    open_count = Incident.query.filter_by(status='open').count()
    total_count = Incident.query.count()
    resolved_count = Incident.query.filter_by(status='resolved').count()

    return render_template('tasks/breach.html', task=task, incidents=incidents,
        open_count=open_count, total_count=total_count, resolved_count=resolved_count,
        current_filter=filter_type)

@main_bp.route('/incident/<int:incident_id>/report')
@login_required
def generate_report(incident_id):
    """generates an article 33 pdf breach report for a specific incident"""
    from app.utils.pdf_report import generate_breach_report
    from flask import send_file

    incident = Incident.query.get_or_404(incident_id)

    # generate the pdf
    filepath, filename = generate_breach_report(incident)

    # mark that a report was generated
    incident.report_generated = True
    incident.report_generated_at = datetime.utcnow()
    db.session.commit()

    # send the file to the user
    return send_file(filepath, as_attachment=True, download_name=filename)

@main_bp.route('/task/ropa/report')
@login_required
def generate_ropa_pdf():
    """generates a pdf of the users data inventory"""
    from app.utils.pdf_report import generate_ropa_report

    records = ROPARecord.query.filter_by(user_id=current_user.id).all()
    if not records:
        flash('No data in your inventory yet.', 'info')
        return redirect(url_for('main.task_ropa'))

    filepath, filename = generate_ropa_report(records)
    return send_file(filepath, as_attachment=True, download_name=filename)

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