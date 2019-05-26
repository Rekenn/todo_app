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

new_list_schema = {
    'type': 'object',
    'properties': {
        'listname': {
            'type': 'string',
            'minLength': 2,
            'maxLength': 32
        }
    },
    'required': ['listname']
}

update_list_schema = {
    'type': 'object',
    'properties': {
        'listname': {
            'type': 'string',
            'minLength': 2,
            'maxLength': 32
        }
    },
    'required': ['listname']
}


new_task_schema = {
    'type': 'object',
    'properties': {
        'text': {
            'type': 'string',
            'minLength': 1,
            'maxLength': 64
        }
    },
    'required': ['text']
}

update_task_schema = {
    'type': 'object',
    'properties': {
        'text': {
            'type': 'string',
            'minLength': 1,
            'maxLength': 64
        },
        'active': {
            'type': 'boolean'
        }
    }
}

search_user_schema = {
    'type': 'object',
    'properties': {
        'username': {
            'type': 'string',
            'minLength': 1,
            'maxLength': 32
        }
    }
}
