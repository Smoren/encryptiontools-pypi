import setuptools

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='encryptiontools',
    author='Smoren',
    author_email='ofigate@gmail.com',
    description='Tools for encryption/decryption. Symmetric and asymmetric (RSA-based) encryption, '
                'signing and verification.',
    keywords='cryptography, encryption, rsa',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Smoren/encryptiontools-pypi',
    project_urls={
        'Documentation': 'https://github.com/Smoren/encryptiontools-pypi',
        'Bug Reports': 'https://github.com/Smoren/encryptiontools-pypi/issues',
        'Source Code': 'https://github.com/Smoren/encryptiontools-pypi',
    },
    package_dir={'': 'src'},
    packages=setuptools.find_packages(where='src'),
    classifiers=[
        # see https://pypi.org/classifiers/
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3 :: Only',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
    install_requires=['rsa', 'cryptography'],
    extras_require={
        'dev': ['check-manifest', 'coverage'],
        'test': ['coverage'],
    },
)
