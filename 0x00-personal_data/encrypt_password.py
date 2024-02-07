#!/usr/bin/env python3
"""module Encrypting passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """functionn hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """function valid hash password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
