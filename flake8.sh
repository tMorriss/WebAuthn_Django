#!/bin/bash

flake8 . --count --ignore=E722,W503 --max-line-length=120 --exclude webauthn/migrations,__init__.py --show-source --statistics --import-order-style smarkets
