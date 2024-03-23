from rest_framework.permissions import BasePermission

class IsAdminUserType(BasePermission):
    """
    Custom permission to only allow users with admin type access.
    """
    def has_permission(self, request, view):
        # Check if the user making the request has admin type
        return request.user.user_type == 'ADMIN'
