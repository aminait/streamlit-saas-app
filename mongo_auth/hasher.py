import bcrypt

class Hasher:
    """
    This class will hash plain text passwords.
    """
    def __init__(self, passwords: list):
        """
        Create a new instance of "Hasher".

        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        """
        self.passwords = passwords

    """
    Hashes the plain text password.

    Parameters
    ----------
    password: str
        The plain text password to be hashed.
    Returns
    -------
    str
        The hashed password.
    """
    def _hash(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    """
    Hashes the list of plain text passwords.

    Returns
    -------
    list
        The list of hashed passwords.
    """
    def generate(self) -> list:
        return [self._hash(password) for password in self.passwords]