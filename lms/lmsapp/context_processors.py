def user_role_context(request):
    is_subadmin = False
    if request.user.is_authenticated:
        is_subadmin = getattr(request.user, 'is_subadmin', False)
    return {
        'is_subadmin': is_subadmin
    }
