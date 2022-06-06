# groupchat

This is a simple groupchat application exposing webservices to authenticated admin and users.
It is extended from https://github.com/flask-admin/flask-admin.git
To run this example:

1. Clone the repository::

     git clone https://github.com/groupchat/groupchat.git
     cd groupchat

2. Create and activate a virtual environment::

     virtualenv env
     source env/bin/activate

3. Install requirements::

     pip3 install -r 'requirements.txt'

4. Run the application::

     python3 app.py

The first time you run this example, a sample sqlite database gets populated automatically. To suppress this behaviour,
comment the following lines in app.py:::

     if not os.path.exists(database_path):
         build_sample_db()

TODO:
1.group add option to user
2.edit user
3.testing
etc
