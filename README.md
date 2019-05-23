# todo_app

## Introduction ##
Todo_app is application which supports organising everyday activities. It allows to create todo lists and share them with every user using application. Every user associated to specific todo list can modify it and can see changes in real time. In this repository there are backend part of application. It is based on Flask microframework and SQLAlchemy object relational mapper.

## Endpoints ##
* Account management endpoints 
    * /register [ POST ]
    * /login [ POST ]
    * /logout_access [ DELETE ] removes session access token
    * /logout_refresh [ DELETE ] removes session refresh token
    * /token [ POST ] renew access token
* Todo list endpoints  
    * /lists  
        * [ GET ] gets all lists associated with user
        * [ POST ] creates new list
    * /lists/\<int:list_id>  
        * [ PUT ] updates list name
        * [ DELETE ] deletes list
    * /lists/\<int:list_id>/tasks  
        * [ GET ] gets all tasks associated with list
        * [ POST ] creates new task
    * /lists/\<int:list_id>/tasks/\<int:task_id>  
        * [ PUT ] updates single task
        * [ DELETE ] deletes single task
* User management endpoints
    * /lists/\<int:list_id>/invite/\<int:user_id> [ POST ] adds user to list
    * /users/search [ POST ] looking for registered users