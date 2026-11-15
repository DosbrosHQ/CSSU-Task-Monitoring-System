import os, csv, io
from datetime import date, datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response
from flask_sqlalchemy import SQLAlchemy
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
    category_id=db.Column(db.Integer, db.ForeignKey('category.id')); assigned_to=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_by=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False); assigned_date=db.Column(db.Date, default=date.today)
    due_date=db.Column(db.Date); priority=db.Column(db.String(20), default='Normal'); instructions=db.Column(db.Text)
    status=db.Column(db.String(30), default='Assigned'); completion_note=db.Column(db.Text)
    started_at=db.Column(db.DateTime); completed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    updated_at=db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    staff=db.relationship('User', foreign_keys=[assigned_to]); assigner=db.relationship('User', foreign_keys=[assigned_by]); category=db.relationship('Category')
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
    if not User.query.first():
        # Set a strong password through Render's ADMIN_PASSWORD environment variable.
        pw=os.environ.get('ADMIN_PASSWORD')
        if not pw:
            pw='ChangeMe123!'
            app.logger.warning('Using starter admin password. Set ADMIN_PASSWORD in Render and change it immediately.')
        db.session.add(User(username='admin', full_name='CSSU Administrator', role='admin', password_hash=generate_password_hash(pw)))
    defaults=[
      ('Receiving and Decontamination',['Receiving/dispatch of used instruments','Sorting and counting instruments','Manual cleaning','Ultrasonic cleaning','Washer-disinfector operation']),
      ('Preparation and Packaging',['Inspection of instruments','Assembly of instrument sets','Packaging and labeling','Indicator placement']),
      ('Sterilization',['Steam sterilizer operation','Cycle monitoring and documentation','Load release and documentation','Biological/chemical indicator monitoring']),
      ('Storage and Distribution',['Sterile stock arrangement','Issuance/distribution of sterile supplies','Inventory monitoring','Expiry/recall checking']),
      ('Quality and Safety',['Equipment inspection','Environmental monitoring','Incident/variance reporting','Quality documentation']),
      ('Other CSSU Activities',['Cleaning and housekeeping','Supply replenishment','Training/orientation','Other assigned duty'])]
    for name, tasks in defaults:
        c=Category.query.filter_by(name=name).first()
        if not c: c=Category(name=name); db.session.add(c); db.session.flush()
        for t in tasks:
            if not TaskOption.query.filter_by(category_id=c.id, task_name=t).first(): db.session.add(TaskOption(category_id=c.id, task_name=t))
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
        try: d=date.fromisoformat(request.form['task_date']); qty=float(request.form.get('quantity') or 0)
        except (ValueError,KeyError): flash('Enter a valid date and quantity.','danger'); return redirect(url_for('tasks'))
        title=request.form.get('task_title','').strip(); status=request.form.get('status','')
        if not title or status not in STATUSES or qty<0: flash('Check the task title, status and quantity.','danger'); return redirect(url_for('tasks'))
        cid=request.form.get('category_id') or None; oid=request.form.get('task_option_id') or None
        log=TaskLog(staff_id=current_user.id,task_date=d,category_id=int(cid) if cid else None,task_option_id=int(oid) if oid else None,
          task_title=title,quantity=qty,status=status,priority=request.form.get('priority','Normal'),start_time=request.form.get('start_time'),end_time=request.form.get('end_time'),
          details=request.form.get('details'),issue=request.form.get('issue'),endorsement=request.form.get('endorsement'),endorsed_to=request.form.get('endorsed_to'))
        db.session.add(log); db.session.commit(); audit('Created task','task',log.id); flash('Task record saved.','success'); return redirect(url_for('tasks'))
    q=TaskLog.query.order_by(TaskLog.task_date.desc(),TaskLog.id.desc())
    if current_user.role!='admin': q=q.filter_by(staff_id=current_user.id)
    return render_template('tasks.html',logs=q.limit(250).all(),categories=Category.query.filter_by(active=True).order_by(Category.name).all(),options=TaskOption.query.filter_by(active=True).all())
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
    return render_template('assignments.html',items=q.limit(300).all(),staff=User.query.filter_by(role='staff',active=True).order_by(User.full_name).all(),categories=Category.query.filter_by(active=True).order_by(Category.name).all())
@app.post('/assignments/create')
@admin_required
def create_assignment():
    try: staff_id=int(request.form['assigned_to']); due=date.fromisoformat(request.form['due_date']) if request.form.get('due_date') else None
    except (ValueError,KeyError): flash('Select a valid staff member and due date.','danger'); return redirect(url_for('assignments'))
    title=request.form.get('title','').strip()
    if not title or not db.session.get(User,staff_id) or db.session.get(User,staff_id).role!='staff': flash('Enter a title and choose an active staff account.','danger'); return redirect(url_for('assignments'))
    cat_raw=request.form.get('category_id') or None
    x=DelegatedTask(title=title,category_id=int(cat_raw) if cat_raw else None,assigned_to=staff_id,assigned_by=current_user.id,due_date=due,priority=request.form.get('priority','Normal'),instructions=request.form.get('instructions'))
    db.session.add(x); db.session.commit(); audit('Delegated task','delegated_task',x.id); flash('Task delegated.','success'); return redirect(url_for('assignments'))
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
@app.route('/admin/categories',methods=['GET','POST'])
@admin_required
def categories_admin():
    if request.method=='POST':
        name=request.form.get('name','').strip()
        if name and not Category.query.filter_by(name=name).first(): db.session.add(Category(name=name)); db.session.commit(); audit('Created category','category'); flash('Category added.','success')
        else: flash('Enter a unique category name.','danger')
        return redirect(url_for('categories_admin'))
    return render_template('categories.html',categories=Category.query.order_by(Category.name).all(),options=TaskOption.query.order_by(TaskOption.task_name).all())
@app.post('/admin/categories/<int:cid>/toggle')
@admin_required
def toggle_category(cid):
    c=db.session.get(Category,cid) or abort(404); c.active=not c.active; db.session.commit(); audit('Changed category active state','category',cid); return redirect(url_for('categories_admin'))
@app.post('/admin/options')
@admin_required
def add_option():
    name=request.form.get('task_name','').strip(); cid=request.form.get('category_id')
    if name and cid: db.session.add(TaskOption(category_id=int(cid),task_name=name)); db.session.commit(); audit('Created task option','task_option'); flash('Task option added.','success')
    return redirect(url_for('categories_admin'))
@app.post('/admin/options/<int:oid>/toggle')
@admin_required
def toggle_option(oid):
    o=db.session.get(TaskOption,oid) or abort(404); o.active=not o.active; db.session.commit(); audit('Changed task option active state','task_option',oid); return redirect(url_for('categories_admin'))
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
