def user_role_context(request):
    is_subadmin = False
    if request.user.is_authenticated:
        is_subadmin = getattr(request.user, 'is_subadmin', False)
    return {
        'is_subadmin': is_subadmin
    }


from .models import Ticket

def open_ticket_count(request):
    if request.user.is_authenticated:
        count = Ticket.objects.filter(status='open').count()
    else:
        count = 0
    return {'open_ticket_count': count}
