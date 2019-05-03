register_schema = {
    'type': 'object',
    'properties': {
        'username': {
            'type': 'string',
            'minLength': 4,
            'maxLength': 32
        },
        'password': {
            'type': 'string',
            'minLength': 6,
            'maxLength': 64
        },
        'password2': {
            'type': 'string',
            'minLength': 6,
            'maxLength': 64
        }
    },
    'required': ['username', 'password', 'password2']
}

login_schema = {
    'type': 'object',
    'properties': {
        'username': {
            'type': 'string',
            'minLength': 4,
            'maxLength': 32
        },
        'password': {
            'type': 'string',
            'minLength': 6,
            'maxLength': 64
        }
    },
    'required': ['username', 'password']  
}

list_schema = {
    'type': 'object',
    'properties': {
        'groupname': {
            'type': 'string',
            'minLength': 2,
            'maxLength': 32
        }
    },
    'required': ['groupname']
}