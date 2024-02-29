test:
	. .tox/py/bin/activate && pytest

coverage:
	. .tox/py/bin/activate && coverage run -m --source=encryptiontools pytest && coverage report -m && coverage html

cov:
	make coverage

tox:
	tox -e py

install:
	pip3 install tox
	tox -e py
