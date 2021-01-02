from .flaskserver import app as flaskapp
import os

# this directory is not autocreated and forces the user to create it/mount it
assert os.path.exists('pins')
app = flaskapp
