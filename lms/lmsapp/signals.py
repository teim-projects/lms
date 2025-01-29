from django.contrib.auth.signals import user_logged_in
from django.contrib.sessions.models import Session
from django.utils.timezone import now
from django.dispatch import receiver
from django.utils.http import urlsafe_base64_encode
import hashlib

@receiver(user_logged_in)
def limit_user_sessions(sender, request, user, **kwargs):
    max_sessions = 2  # Allow only 2 active sessions per user
    browser_identifier = hashlib.md5(request.META.get('HTTP_USER_AGENT', '').encode('utf-8')).hexdigest()

    # Create a unique session identifier using the user and browser info
    session_key_identifier = f"{user.id}_{browser_identifier}"

    # Get all active sessions for the user and browser combination
    sessions = Session.objects.filter(session_key__contains=session_key_identifier)
    user_sessions = []

    for session in sessions:
        session_data = session.get_decoded()
        if session_data.get('_auth_user_id') == str(user.id):
            user_sessions.append(session)

    # If the number of sessions exceeds the limit, delete the oldest session(s)
    if len(user_sessions) > max_sessions:
        user_sessions.sort(key=lambda s: s.expire_date)  # Sort by expiry date
        for session_to_delete in user_sessions[:-max_sessions]:
            session_to_delete.delete()
