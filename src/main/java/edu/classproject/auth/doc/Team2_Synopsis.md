# Team 2 - BitBees  Synopsis

This module focuses on implementing authentication and session management for the Food Delivery Application. The primary objective is to ensure secure access by validating user credentials and maintaining user sessions.

The AuthService component provides functionalities such as login, logout, and session validation. During login, credentials are verified using the User module, and upon successful authentication, a session is created with a unique session ID and expiry time. Invalid credentials do not result in session creation.

The Session entity stores session details such as session ID, user ID, creation time, and expiry time. Session expiry logic ensures that expired sessions are automatically invalidated. The AuthRepository manages storing, retrieving, and deleting session data.

The UML diagrams for this module are located in the path:
src/main/java/edu/classproject/auth/doc/
and include:

* Class Diagram: ![Class Diagram](src/main/java/edu/classproject/auth/doc/Team2_Class_Diagram.png)
* Sequence Diagram (Login): ![Login](src/main/java/edu/classproject/auth/doc/Team2_Sequence_Diagram_Login.png)
* Sequence Diagram (Logout): ![Logout](src/main/java/edu/classproject/auth/doc/Team2_Sequence_Diagram_Logout.png)
* Sequence Diagram (Session Validation): ![Validation](src/main/java/edu/classproject/auth/doc/Team2_Sequence_Diagram_Session_Validation.png)

The implementation follows the designed UML diagrams and ensures modularity, proper separation of concerns, and secure session handling. Test cases are included to verify session creation, expiry behavior, and invalid credential handling.
