import os, csv, io
from datetime import date, datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///cssu_monitor_web.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-only-change-this-secret-before-deploying'),
    SQLALCHEMY_DATABASE_URI=database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('RENDER', '') == 'true',
    PERMANENT_SESSION_LIFETIME=__import__('datetime').timedelta(hours=8),
)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app); login_manager.login_view = 'login'
STATUSES = ['Completed', 'Ongoing', 'Pending', 'Unresolved', 'Cancelled']
PRIORITIES = ['Low', 'Normal', 'High', 'Urgent']

class User(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True); username=db.Column(db.String(80), unique=True, nullable=False)
    full_name=db.Column(db.String(160), nullable=False); role=db.Column(db.String(10), nullable=False)
    password_hash=db.Column(db.String(255), nullable=False); active=db.Column(db.Boolean, default=True, nullable=False)
    created_at=db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
class Category(db.Model):
    id=db.Column(db.Integer, primary_key=True); name=db.Column(db.String(160), unique=True, nullable=False); active=db.Column(db.Boolean, default=True)
class TaskOption(db.Model):
    id=db.Column(db.Integer, primary_key=True); category_id=db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    task_name=db.Column(db.String(200), nullable=False); active=db.Column(db.Boolean, default=True)
    indicator_type=db.Column(db.String(12), nullable=False, default='regular'); notes=db.Column(db.Text, default='')
    category=db.relationship('Category')
class TaskLog(db.Model):
    id=db.Column(db.Integer, primary_key=True); staff_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_date=db.Column(db.Date, nullable=False); category_id=db.Column(db.Integer, db.ForeignKey('category.id'))
    task_option_id=db.Column(db.Integer, db.ForeignKey('task_option.id')); task_title=db.Column(db.String(240), nullable=False)
    quantity=db.Column(db.Float, default=0); status=db.Column(db.String(30), nullable=False); priority=db.Column(db.String(20), nullable=False)
    start_time=db.Column(db.String(20)); end_time=db.Column(db.String(20)); details=db.Column(db.Text); issue=db.Column(db.Text)
    endorsement=db.Column(db.Text); endorsed_to=db.Column(db.String(160)); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    updated_at=db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    staff=db.relationship('User'); category=db.relationship('Category')
class DelegatedTask(db.Model):
    id=db.Column(db.Integer, primary_key=True); title=db.Column(db.String(240), nullable=False)
    category_id=db.Column(db.Integer, db.ForeignKey('category.id')); task_option_id=db.Column(db.Integer, db.ForeignKey('task_option.id'))
    assigned_to=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_by=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False); assigned_date=db.Column(db.Date, default=date.today)
    due_date=db.Column(db.Date); priority=db.Column(db.String(20), default='Normal'); instructions=db.Column(db.Text)
    status=db.Column(db.String(30), default='Assigned'); completion_note=db.Column(db.Text)
    started_at=db.Column(db.DateTime); completed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    updated_at=db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    staff=db.relationship('User', foreign_keys=[assigned_to]); assigner=db.relationship('User', foreign_keys=[assigned_by]); category=db.relationship('Category'); indicator=db.relationship('TaskOption')
class AuditLog(db.Model):
    id=db.Column(db.Integer, primary_key=True); user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
    action=db.Column(db.String(240), nullable=False); record_type=db.Column(db.String(60)); record_id=db.Column(db.Integer)
    timestamp=db.Column(db.DateTime, default=datetime.utcnow); user=db.relationship('User')

@login_manager.user_loader
def load_user(uid): return db.session.get(User, int(uid))
def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*a, **kw):
        if current_user.role != 'admin': abort(403)
        return fn(*a, **kw)
    return wrapped
def audit(action, kind=None, rid=None):
    db.session.add(AuditLog(user_id=current_user.id, action=action, record_type=kind, record_id=rid)); db.session.commit()
def seed():
    db.create_all()
    # Add missing columns without dropping or resetting existing records.
    with db.engine.begin() as conn:
        option_cols={c["name"] for c in inspect(db.engine).get_columns("task_options")}
        if "indicator_type" not in option_cols:
            conn.exec_driver_sql("ALTER TABLE task_options ADD COLUMN indicator_type VARCHAR(12) NOT NULL DEFAULT 'regular'")
        if "notes" not in option_cols:
            conn.exec_driver_sql("ALTER TABLE task_options ADD COLUMN notes TEXT")
        delegation_cols={c["name"] for c in inspect(db.engine).get_columns("delegated_tasks")}
        if "task_option_id" not in delegation_cols:
            conn.exec_driver_sql("ALTER TABLE delegated_tasks ADD COLUMN task_option_id INTEGER")
    if not User.query.first():
        pw=os.environ.get('ADMIN_PASSWORD')
        if not pw:
            pw='ChangeMe123!'
            app.logger.warning('Using starter admin password. Set ADMIN_PASSWORD in Render and change it immediately.')
        db.session.add(User(username='admin',full_name='CSSU Administrator',role='admin',password_hash=generate_password_hash(pw)))
    defaults=[
      ('Strategic Functions',[
        ('Attended Information Dissemination','admin','Attended the dissemination of information in the conducted monthly meeting of non-clinical nursing units per semester'),
        ('Attended Strategic Monitoring','regular','Attended the scheduled monthly strategic monitoring for non-clinical nursing units and cascaded relevant information during the area monthly meetings within the prescribed timeline.')
      ]),
      ('Core Functions',[
        ('Attended Information Dissemination','regular','Attended the dissemination of information in the conducted monthly meeting of Nurse supervisor per semester'),
        ('Attend LDI','regular','Attending in at least one (1) Leadership Development Initiative (LDI) per semester, with complete documentation properly filed.'),
        ('Create and Submit Monthly Inventory','regular','Creation and submission of duly signed monthly inventory reports within the set deadlines, with no identified errors.'),
        ('Preparation and Release of Supplies','regular','Ensure 100% accuracy in the preparation and release of all available medical supplies requested via Medix System and RIS forms, with no recorded discrepancies'),
        ('Reproduction of Forms','regular','Ensure the reproduction of hospital-coded forms within the given timeline.'),
        ('Consolidation of NBB attachments','regular','Ensure timely and accurate (100%) consolidation of NBB attachments, with no identified discrepancies, within the given timeframe'),
        ('Request through Wish System','regular','Maintain 100% accuracy in the requisition and collection of medical supplies requested through the WISH system, with zero recorded discrepancies.'),
        ('Participation in NPIS Phase 2','regular','Participation in the implementation of NPIS Phase 2 in the unit within the given timeline'),
        ('Sterilization for Medical Instruments','regular','Sterilization procedures for all medical instruments were completed within the defined timeframe in accordance with established standards.'),
        ('Monitor Reported Incidents','admin','100% monitoring and documentation of all identified reportable incidents were completed within the specified timeframe.'),
        ('Incidents Reported','admin','All identified reportable incidents are documented within the prescribed timeframe'),
        ('Attend Nurse Supervisors Meeting','admin','Attended all the monthly meetings of the Nurse Supervisors conducted by the Nursing Service Division within the semester.'),
        ('PPMP Consolidation','admin','Consolidation and submission of duly signed Indicative PPMP of the Nursing Service Division for 2027 within the prescribed timeline'),
        ('Standard Registry for Medical Supplies','admin','Creation and submission of approved standardized registry for medical supplies within the prescribed timeline.'),
        ('Submit Documents for RFAs','admin','Ensuring the timely compliance and submission of all required documents for RFAs within the given timeline'),
        ('Monitor Compliance of staff in NPIS Phase 2','admin','Monitoring of staff compliance in the implementation of NPIS Phase 2 in the unit within the prescribed period'),
        ('Monitor Inventory Reports','admin','Monitoring of submitted duly signed inventory reports within the given timeline.'),
        ('Monitor Signed Monthly Schedule','admin','Monitoring of submitted of duly signed monthly schedules for the non-clinical nursing units within the semester.'),
        ('Monitor Reproduction of Froms','admin','Monitoring the accuracy and complete reproduction of controlled hospital forms throughout the semester'),
        ('Monitor Entries on WISH Systems','admin','Monitoring the completeness and quality of medical supplies collected through the WISH system'),
        ('Monitor Supplies on Medix and RIS','admin','Monitoring the completeness of requested medical supplies through Medix System and RIS form and released with no recorded discrepancies'),
        ('Monitor Staff Involvement in LDI','admin','Participation in and monitoring staff involvement in at least one (1) Leadership Development Initiative (LDI) per semester with complete documentation on file'),
        ('Submit Monthly Schedule','admin','Prepared and submitted duly signed monthly schedules for the units within the prescribed timeline.'),
        ('Submit Signed NBB','admin','Submission of duly signed documents and monitoring of at least one (1) NBB fund replenishment within the semester.')
      ]),
      ('Support Functions',[
        ('Monitor Submitted Documents','admin','Monitoring of staff adherence to the submission of all mandatory statutory and regulatory documents with no corrections required within the given period.'),
        ('Submitted Precise Documents','regular','Submission of mandatory statutory and regulatory documents was completed within the semester with no corrections needed.')
      ])
    ]
    for old_name in ['Receiving and Decontamination','Preparation and Packaging','Sterilization','Storage and Distribution','Quality and Safety','Other CSSU Activities']:
        old=Category.query.filter_by(name=old_name).first()
        if old: old.active=False
    for category_name,indicators in defaults:
        category=Category.query.filter_by(name=category_name).first()
        if not category:
            category=Category(name=category_name); db.session.add(category); db.session.flush()
        category.active=True
        for indicator_name,indicator_type,indicator_notes in indicators:
            option=TaskOption.query.filter_by(category_id=category.id,task_name=indicator_name).first()
            if not option:
                option=TaskOption(category_id=category.id,task_name=indicator_name); db.session.add(option)
            option.active=True
            option.indicator_type=indicator_type
            if not option.notes: option.notes=indicator_notes
    db.session.commit()

@app.context_processor
def globals_for_templates(): return {'STATUSES':STATUSES,'PRIORITIES':PRIORITIES,'today':date.today()}
@app.route('/')
def index(): return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=User.query.filter_by(username=request.form.get('username','').strip(), active=True).first()
        if u and check_password_hash(u.password_hash, request.form.get('password','')):
            login_user(u); audit('Signed in'); return redirect(url_for('dashboard'))
        flash('Invalid username or password.','danger')
    return render_template('login.html')
@app.post('/logout')
@login_required
def logout(): audit('Signed out'); logout_user(); return redirect(url_for('login'))
@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method=='POST':
        old=request.form.get('current_password',''); new=request.form.get('new_password','')
        if not check_password_hash(current_user.password_hash,old): flash('Current password is incorrect.','danger')
        elif len(new)<12: flash('Use a password with at least 12 characters.','danger')
        elif new != request.form.get('confirm_password'): flash('New passwords do not match.','danger')
        else:
            current_user.password_hash=generate_password_hash(new); db.session.commit(); audit('Changed password'); flash('Password updated.','success'); return redirect(url_for('dashboard'))
    return render_template('password.html')
@app.route('/dashboard')
@login_required
def dashboard():
    month=request.args.get('month',date.today().strftime('%Y-%m'))
    try: start=date.fromisoformat(month+'-01'); end=date(start.year+start.month//12, start.month%12+1,1)
    except ValueError: month=date.today().strftime('%Y-%m'); start=date.today().replace(day=1); end=date(start.year+start.month//12,start.month%12+1,1)
    q=TaskLog.query.filter(TaskLog.task_date>=start,TaskLog.task_date<end)
    if current_user.role!='admin': q=q.filter_by(staff_id=current_user.id)
    logs=q.all(); assignments=DelegatedTask.query.filter(DelegatedTask.status.in_(['Assigned','In Progress']))
    if current_user.role!='admin': assignments=assignments.filter_by(assigned_to=current_user.id)
    counts={s:sum(x.status==s for x in logs) for s in STATUSES}
    staff_counts={}
    for x in logs: staff_counts[x.staff.full_name]=staff_counts.get(x.staff.full_name,0)+1
    return render_template('dashboard.html',month=month,logs=logs,counts=counts,staff_counts=staff_counts,open_count=assignments.count())
@app.route('/tasks', methods=['GET','POST'])
@login_required
def tasks():
    if request.method=='POST':
        try:
            d=date.fromisoformat(request.form['task_date'])
            qty=float(request.form.get('quantity') or 0)
            indicator_id=int(request.form.get('indicator_id') or 0)
        except (ValueError,KeyError):
            flash('Enter a valid date, quantity and indicator.','danger')
            return redirect(url_for('tasks'))
        option=db.session.get(TaskOption,indicator_id)
        if not option or not option.active or not option.category.active or (option.indicator_type=='admin' and current_user.role!='admin') or qty<0:
            abort(400)
        status=request.form.get('status','')
        if status not in STATUSES: abort(400)
        note=request.form.get('details','').strip() or (option.notes or '')
        log=TaskLog(staff_id=current_user.id,task_date=d,category_id=option.category_id,task_option_id=option.id,
          task_title=option.task_name,quantity=qty,status=status,priority=request.form.get('priority','Normal'),
          start_time=request.form.get('start_time'),end_time=request.form.get('end_time'),details=note,
          issue=request.form.get('issue'),endorsement=request.form.get('endorsement'),endorsed_to=request.form.get('endorsed_to'))
        db.session.add(log); db.session.commit(); audit('Created indicator record','indicator',log.id)
        flash('Indicator record saved.','success')
        return redirect(url_for('tasks'))
    q=TaskLog.query.order_by(TaskLog.task_date.desc(),TaskLog.id.desc())
    if current_user.role!='admin': q=q.filter_by(staff_id=current_user.id)
    option_q=TaskOption.query.join(Category).filter(TaskOption.active.is_(True),Category.active.is_(True))
    if current_user.role!='admin': option_q=option_q.filter(TaskOption.indicator_type=='regular')
    options=option_q.order_by(Category.name,TaskOption.task_name).all()
    return render_template('tasks.html',logs=q.limit(250).all(),
        categories=Category.query.filter_by(active=True).order_by(Category.name).all(),options=options)

@app.post('/tasks/<int:tid>/update')
@login_required
def update_task(tid):
    x=db.session.get(TaskLog,tid) or abort(404)
    if current_user.role!='admin' and x.staff_id!=current_user.id: abort(403)
    x.status=request.form.get('status',x.status); x.priority=request.form.get('priority',x.priority)
    x.endorsement=request.form.get('endorsement',x.endorsement); x.endorsed_to=request.form.get('endorsed_to',x.endorsed_to)
    x.issue=request.form.get('issue',x.issue); db.session.commit(); audit('Updated task','task',x.id); flash('Task updated.','success'); return redirect(url_for('tasks'))
@app.route('/assignments')
@login_required
def assignments():
    q=DelegatedTask.query.order_by(DelegatedTask.due_date.asc().nullslast(),DelegatedTask.id.desc())
    if current_user.role!='admin': q=q.filter_by(assigned_to=current_user.id)
    options=TaskOption.query.join(Category).filter(TaskOption.active.is_(True),Category.active.is_(True)).order_by(Category.name,TaskOption.task_name).all()
    return render_template('assignments.html',items=q.limit(300).all(),
        staff=User.query.filter_by(role='staff',active=True).order_by(User.full_name).all(),
        categories=Category.query.filter_by(active=True).order_by(Category.name).all(),options=options)
@app.post('/assignments/create')
@admin_required
def create_assignment():
    try:
        staff_id=int(request.form['assigned_to'])
        indicator_id=int(request.form['indicator_id'])
        due=date.fromisoformat(request.form['due_date']) if request.form.get('due_date') else None
    except (ValueError,KeyError):
        flash('Select a valid staff member, indicator and due date.','danger')
        return redirect(url_for('assignments'))
    member=db.session.get(User,staff_id); option=db.session.get(TaskOption,indicator_id)
    if not member or member.role!='staff' or not member.active or not option or not option.active or not option.category.active:
        flash('Choose an active staff account and an active indicator.','danger')
        return redirect(url_for('assignments'))
    x=DelegatedTask(title=option.task_name,category_id=option.category_id,task_option_id=option.id,
        assigned_to=staff_id,assigned_by=current_user.id,due_date=due,priority=request.form.get('priority','Normal'),
        instructions=request.form.get('instructions','').strip() or (option.notes or ''))
    db.session.add(x); db.session.commit(); audit('Delegated indicator','delegated_indicator',x.id)
    flash('Indicator delegated.','success')
    return redirect(url_for('assignments'))
@app.post('/assignments/<int:tid>/update')
@login_required
def update_assignment(tid):
    x=db.session.get(DelegatedTask,tid) or abort(404)
    if current_user.role!='admin' and x.assigned_to!=current_user.id: abort(403)
    status=request.form.get('status',x.status); note=request.form.get('completion_note','').strip()
    if status not in ['Assigned','In Progress','Completed','Unable to Complete']: abort(400)
    if status in ['Completed','Unable to Complete'] and not note: flash('A note is required for completed or unable-to-complete tasks.','danger'); return redirect(url_for('assignments'))
    x.status=status; x.completion_note=note
    if status=='In Progress' and not x.started_at: x.started_at=datetime.utcnow()
    if status in ['Completed','Unable to Complete']: x.completed_at=datetime.utcnow()
    db.session.commit(); audit('Updated delegated task','delegated_task',x.id); flash('Assignment updated.','success'); return redirect(url_for('assignments'))
@app.route('/admin/staff',methods=['GET','POST'])
@admin_required
def staff_admin():
    if request.method=='POST':
        username=request.form.get('username','').strip(); name=request.form.get('full_name','').strip()
        if not username or not name or User.query.filter_by(username=username).first(): flash('Enter a unique username and full name.','danger')
        else:
            u=User(username=username,full_name=name,role='staff',password_hash=generate_password_hash('TempPass123!')); db.session.add(u); db.session.commit(); audit('Created staff account','user',u.id); flash('Staff account created. Temporary password: TempPass123! Ask the user to change it immediately.','success')
        return redirect(url_for('staff_admin'))
    return render_template('staff.html',users=User.query.order_by(User.full_name).all())
@app.post('/admin/staff/<int:uid>/toggle')
@admin_required
def toggle_staff(uid):
    u=db.session.get(User,uid) or abort(404)
    if u.id==current_user.id: flash('You cannot deactivate your own account.','danger')
    else: u.active=not u.active; db.session.commit(); audit('Changed staff account active state','user',u.id); flash('Account status updated.','success')
    return redirect(url_for('staff_admin'))
@app.post('/admin/staff/<int:uid>/delete')
@admin_required
def delete_staff(uid):
    u=db.session.get(User,uid) or abort(404)
    if u.id==current_user.id:
        flash('You cannot delete your own account.','danger')
        return redirect(url_for('staff_admin'))
    history=(TaskLog.query.filter_by(staff_id=uid).first() or
        DelegatedTask.query.filter((DelegatedTask.assigned_to==uid)|(DelegatedTask.assigned_by==uid)).first() or
        AuditLog.query.filter_by(user_id=uid).first())
    if history:
        u.active=False
        action='Deactivated staff account with history'
        flash('Account has historical records; it was deactivated to preserve the audit trail.','warning')
    else:
        db.session.delete(u)
        action='Deleted staff account'
        flash('Staff account deleted.','success')
    db.session.commit(); audit(action,'user',uid)
    return redirect(url_for('staff_admin'))

@app.route('/admin/categories',methods=['GET','POST'])
@admin_required
def categories_admin():
    if request.method=='POST':
        name=request.form.get('name','').strip()
        if name and not Category.query.filter_by(name=name).first():
            db.session.add(Category(name=name)); db.session.commit(); audit('Created category','category')
            flash('Category added.','success')
        else: flash('Enter a unique category name.','danger')
        return redirect(url_for('categories_admin'))
    return render_template('categories.html',categories=Category.query.order_by(Category.name).all(),
        options=TaskOption.query.order_by(TaskOption.task_name).all())
@app.post('/admin/categories/<int:cid>/toggle')
@admin_required
def toggle_category(cid):
    c=db.session.get(Category,cid) or abort(404); c.active=not c.active
    db.session.commit(); audit('Changed category active state','category',cid)
    return redirect(url_for('categories_admin'))
@app.post('/admin/categories/<int:cid>/delete')
@admin_required
def delete_category(cid):
    c=db.session.get(Category,cid) or abort(404)
    used=(TaskLog.query.filter_by(category_id=cid).first() or DelegatedTask.query.filter_by(category_id=cid).first() or
          TaskLog.query.join(TaskOption,TaskLog.task_option_id==TaskOption.id).filter(TaskOption.category_id==cid).first() or
          DelegatedTask.query.join(TaskOption,DelegatedTask.task_option_id==TaskOption.id).filter(TaskOption.category_id==cid).first())
    if used:
        c.active=False; TaskOption.query.filter_by(category_id=cid).update({TaskOption.active:False})
        action='Deactivated category with history'
        flash('Category has historical records; it and its indicators were deactivated.','warning')
    else:
        TaskOption.query.filter_by(category_id=cid).delete(synchronize_session=False); db.session.delete(c)
        action='Deleted category'; flash('Category and its indicators deleted.','success')
    db.session.commit(); audit(action,'category',cid)
    return redirect(url_for('categories_admin'))
@app.post('/admin/options')
@admin_required
def add_option():
    name=request.form.get('task_name','').strip(); cid=request.form.get('category_id')
    kind=request.form.get('indicator_type','regular'); notes=request.form.get('notes','').strip()
    if name and cid and kind in ['regular','admin']:
        db.session.add(TaskOption(category_id=int(cid),task_name=name,indicator_type=kind,notes=notes))
        db.session.commit(); audit('Created indicator','indicator'); flash('Indicator added.','success')
    else: flash('Enter an indicator name, category and designation.','danger')
    return redirect(url_for('categories_admin'))
@app.post('/admin/options/<int:oid>/update')
@admin_required
def update_option(oid):
    o=db.session.get(TaskOption,oid) or abort(404)
    name=request.form.get('task_name','').strip(); kind=request.form.get('indicator_type','regular')
    if not name or kind not in ['regular','admin']:
        flash('Enter a valid indicator name and designation.','danger')
    else:
        o.task_name=name; o.indicator_type=kind; o.notes=request.form.get('notes','').strip()
        db.session.commit(); audit('Updated indicator','indicator',oid); flash('Indicator updated.','success')
    return redirect(url_for('categories_admin'))
@app.post('/admin/options/<int:oid>/toggle')
@admin_required
def toggle_option(oid):
    o=db.session.get(TaskOption,oid) or abort(404); o.active=not o.active
    db.session.commit(); audit('Changed indicator active state','indicator',oid)
    return redirect(url_for('categories_admin'))
@app.post('/admin/options/<int:oid>/delete')
@admin_required
def delete_option(oid):
    o=db.session.get(TaskOption,oid) or abort(404)
    used=TaskLog.query.filter_by(task_option_id=oid).first() or DelegatedTask.query.filter_by(task_option_id=oid).first()
    if used:
        o.active=False; action='Deactivated indicator with history'
        flash('Indicator has historical records; it was deactivated to preserve records.','warning')
    else:
        db.session.delete(o); action='Deleted indicator'; flash('Indicator deleted.','success')
    db.session.commit(); audit(action,'indicator',oid)
    return redirect(url_for('categories_admin'))

@app.post('/assignments/<int:tid>/delete')
@admin_required
def delete_assignment(tid):
    x=db.session.get(DelegatedTask,tid) or abort(404)
    label=x.title; db.session.delete(x); db.session.commit()
    audit('Deleted delegated indicator: '+label,'delegated_indicator',tid)
    flash('Delegation deleted.','success')
    return redirect(url_for('assignments'))

@app.route('/export.csv')
@login_required
def export_csv():
    month=request.args.get('month',date.today().strftime('%Y-%m'))
    q=TaskLog.query.filter(db.cast(TaskLog.task_date,db.String).like(month+'%')).order_by(TaskLog.task_date,TaskLog.id)
    if current_user.role!='admin': q=q.filter_by(staff_id=current_user.id)
    out=io.StringIO(); w=csv.writer(out); w.writerow(['Date','Staff','Category','Task','Quantity','Status','Priority','Start','End','Details','Issue','Endorsement','Endorsed To'])
    for x in q.all(): w.writerow([x.task_date,x.staff.full_name,x.category.name if x.category else '',x.task_title,x.quantity,x.status,x.priority,x.start_time,x.end_time,x.details,x.issue,x.endorsement,x.endorsed_to])
    resp=make_response('\ufeff'+out.getvalue()); resp.headers['Content-Type']='text/csv; charset=utf-8'; resp.headers['Content-Disposition']=f'attachment; filename=CSSU_Tasks_{month}.csv'; return resp
@app.route('/admin/audit')
@admin_required
def audit_page(): return render_template('audit.html',items=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(300).all())
@app.errorhandler(403)
def forbidden(e): return render_template('error.html',code=403,message='You do not have permission to access this page.'),403
@app.errorhandler(404)
def not_found(e): return render_template('error.html',code=404,message='The requested page was not found.'),404

with app.app_context(): seed()
if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False)
