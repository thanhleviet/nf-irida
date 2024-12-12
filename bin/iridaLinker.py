#!/usr/bin/env python3

import os
import sys
import json
import argparse
import getpass
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union
import requests
from urllib.parse import urljoin
import configparser
import re

VERSION = '1.0.0'

# Update constants for duplicate handling
class DuplicateHandling:
    FAIL = 'fail'
    IGNORE = 'ignore'
    RENAME = 'rename'

DEFAULT_CONFIG_LOCATIONS = [
    os.environ.get('IRIDA_CONFIG_FILE'),
    os.path.join(os.path.dirname(__file__), "irida.conf"),
    os.path.expanduser("~/.irida/config.conf")
]

def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configure and return a logger instance"""
    logger = logging.getLogger('IRIDALinker')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create console handler with formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    
    return logger

class IRIDALinker:
    def __init__(self, logger: logging.Logger):
        # Initialize counters for tracking file operations
        self.file_count = 0
        self.ignore_count = 0
        
        # OAuth2 client credentials
        self.client_id = "defaultLinker"
        self.client_secret = "defaultLinkerSecret"
        
        self.session = requests.Session()
        self.base_url = None
        self.logger = logger

    def _build_url(self, endpoint: str) -> str:
        """Build a proper URL by handling the /api prefix correctly"""
        # Extract the base part of the URL (before /irida/api)
        base = self.base_url.split('/irida/api')[0]
        # Remove any trailing slashes
        base = base.rstrip('/')
        # Remove leading slash from endpoint if it exists
        endpoint = endpoint.lstrip('/')
        # Construct the full URL with the correct path structure
        return f"{base}/irida/api/{endpoint}"

    def get_token(self, base_url: str, username: str, password: str) -> str:
        """Get OAuth2 token using password flow as defined in the API schema"""
        self.base_url = base_url
        token_url = self._build_url('oauth/token')
        
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': 'read write'
        }
        
        try:
            self.logger.debug(f"Attempting to get token from: {token_url}")
            response = requests.post(token_url, data=data)
            
            self.logger.debug(f"Response status code: {response.status_code}")
            self.logger.debug(f"Response headers: {response.headers}")
            self.logger.debug(f"Response content: {response.content}")
            
            if not response.ok:
                try:
                    oauth_info = response.json()
                    error_msg = oauth_info.get('error', '')
                    error_desc = oauth_info.get('error_description', '')
                    self.logger.error(f"Couldn't get OAuth token: {response.status_code}")
                    self.logger.error(f"{error_msg}: {error_desc}" if error_desc else error_msg)
                except json.JSONDecodeError:
                    self.logger.error(f"Couldn't get OAuth token: {response.status_code}")
                    self.logger.error(f"Raw response: {response.content}")
                sys.exit(1)
                
            self.logger.debug("Successfully obtained OAuth token")
            return response.json()['access_token']
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON response: {str(e)}")
            self.logger.error(f"Raw response: {response.content}")
            raise

    def validate_admin_access(self, username: str) -> bool:
        """Check if user has admin role by first getting user ID and then checking details"""
        try:
            # First get all users to find the ID for the given username
            response = self.session.get(
                self._build_url('users'),
                headers={'Accept': 'application/json'}
            )
            self._check_response_code(response, 'users list')
            
            users_data = response.json()
            if 'resource' not in users_data or 'resources' not in users_data['resource']:
                self.logger.error("Invalid response format from users endpoint")
                return False
                
            # Find the user ID for the given username
            user_id = None
            for user in users_data['resource']['resources']:
                if user.get('username') == username:
                    user_id = user.get('identifier')
                    break
                    
            if not user_id:
                self.logger.error(f"Could not find user ID for username: {username}")
                return False
                
            # Now get the specific user details using the ID
            response = self.session.get(
                self._build_url(f'users/{user_id}'),
                headers={'Accept': 'application/json'}
            )
            self._check_response_code(response, f'user details for ID {user_id}')
            
            user_data = response.json()
            if 'resource' not in user_data:
                return False
                
            system_role = user_data['resource'].get('systemRole')
            is_admin = system_role == 'ROLE_ADMIN'
            
            if not is_admin:
                self.logger.error(f"User {username} does not have admin privileges")
            else:
                self.logger.debug(f"Verified admin access for user {username}")
                
            return is_admin
            
        except Exception as e:
            self.logger.error(f"Error validating admin access: {str(e)}")
            return False

    def check_email_permission(self, project_id: str, email: str) -> bool:
        """Check if email has project access using the projects/users endpoint"""
        try:
            response = self.session.get(
                self._build_url(f'projects/{project_id}/users'),
                headers={'Accept': 'application/json'}
            )
            self._check_response_code(response, f'project users')
            
            users_data = response.json()
            if 'resource' not in users_data or 'resources' not in users_data['resource']:
                return False
                
            for user in users_data['resource']['resources']:
                if user.get('email') == email:
                    self.logger.debug(f"Email {email} has permission to access the project")
                    return True
                    
            self.logger.error(f"Email {email} does not have permission to access this project")
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking email permissions: {str(e)}")
            return False

    def build_project_url(self, project_id: str) -> str:
        """Build project URL using the API schema paths"""
        return urljoin(self.base_url, f'/api/projects/{project_id}')

    def get_project(self, project_id: str) -> Dict:
        """Get project details using the projects endpoint"""
        url = self._build_url(f'projects/{project_id}')
        response = self.session.get(url, headers={'Accept': 'application/json'})
        self._check_response_code(response, url)
        return response.json()

    def get_project_samples(self, project_id: str) -> List[Dict]:
        """Get project samples using the projects/samples endpoint"""
        url = self._build_url(f'projects/{project_id}/samples')
        response = self.session.get(url, headers={'Accept': 'application/json'})
        self._check_response_code(response, url)
        data = response.json()
        return data['resource']['resources'] if 'resource' in data else []

    def get_sample_files(self, sample_id: str, file_type: str) -> List[Dict]:
        """Get sample files using the appropriate endpoint based on file type"""
        if file_type == 'fastq':
            url = self._build_url(f'samples/{sample_id}/sequenceFiles')
        elif file_type == 'assembly':
            url = self._build_url(f'samples/{sample_id}/assemblies')
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
            
        response = self.session.get(url, headers={'Accept': 'application/json'})
        self._check_response_code(response, url)
        data = response.json()
        return data['resource']['resources'] if 'resource' in data else []

    def check_server_status(self, base_url: str):
        """Check if the server is available"""
        response = self.session.get(self._build_url(''), headers={'Accept': 'application/json'})
        self._check_response_code(response, base_url)

    def _check_response_code(self, response: requests.Response, url: str):
        """Check response code and handle errors"""
        if response.status_code == 401:
            self.logger.error("Username or password are incorrect.")
            sys.exit(1)
        elif response.status_code == 500:
            self.logger.error("Server returned internal server error. You may have used an incorrect URL for the API.")
            sys.exit(1)
        elif response.status_code == 403:
            self.logger.error(f"This user does not have access to the resource at {url}.")
            sys.exit(1)
        elif response.status_code == 404:
            self.logger.error(f"Requested resource wasn't found at {url}.")
            sys.exit(1)
        elif response.status_code != 200:
            self.logger.error(f"Server returned status code {response.status_code} when requesting resource {url}.")
            sys.exit(1)

    def _check_file_existence(self, new_file: str, duplicate_handling: str) -> Optional[str]:
        """Check if a file exists and handle according to duplicate_handling strategy"""
        if os.path.exists(new_file) or os.path.islink(new_file):
            if duplicate_handling == DuplicateHandling.FAIL:
                self.logger.error(f"File {new_file} already exists")
                self.logger.info("Use --duplicate-handling=ignore to skip existing files, "
                               "or --duplicate-handling=rename to create unique filenames.")
                sys.exit(1)
            elif duplicate_handling == DuplicateHandling.IGNORE:
                self.logger.debug(f"Skipping {new_file} as it already exists.")
                self.ignore_count += 1
                return None
            elif duplicate_handling == DuplicateHandling.RENAME:
                self.logger.debug(f"File {new_file} exists. Creating unique filename.")
                return self._check_available_filename(new_file)
        return new_file

    def _check_available_filename(self, filename: str) -> str:
        """Find an available filename by appending _N to the base name"""
        base_id = 0
        while os.path.exists(filename) or os.path.islink(filename):
            base_id += 1
            if re.search(r'_\d+$', filename):
                filename = re.sub(r'_\d+$', f'_{base_id}', filename)
            else:
                filename = f"{filename}_{base_id}"
        return filename

    def generate_project_csv(self, project_id: str, output_dir: str, 
                           specific_samples: Optional[List[str]] = None) -> str:
        """Generate a CSV file containing sample information and file paths"""
        # Get project details
        project = self.get_project(project_id)
        project_name = project['resource']['name']
        project_samples = self.get_project_samples(project_id)
        
        csv_path = os.path.join(output_dir, f"{project_name}_samples.csv")
        
        with open(csv_path, 'w') as f:
            f.write("sample_name,fastq1,fastq2\n")
            
            for sample in project_samples:
                sample_id = sample['identifier']
                sample_name = sample['sampleName']
                
                if specific_samples and sample_id not in specific_samples:
                    continue
                
                fastq_files = self.get_sample_files(sample_id, 'fastq')
                fastq_files.sort(key=lambda x: x['file'])  # Ensure R1 before R2
                
                fastq1 = fastq_files[0]['file'] if len(fastq_files) > 0 else ''
                fastq2 = fastq_files[1]['file'] if len(fastq_files) > 1 else ''
                
                f.write(f"{sample_name},{fastq1},{fastq2}\n")
        
        self.logger.info(f"Created CSV file at {csv_path}")
        return csv_path

    def check_email_admin_status(self, email: str) -> bool:
        """Check if the provided email has admin role"""
        try:
            # Get all users
            response = self.session.get(
                self._build_url('users'),
                headers={'Accept': 'application/json'}
            )
            self._check_response_code(response, 'users list')
            
            users_data = response.json()
            if 'resource' not in users_data or 'resources' not in users_data['resource']:
                self.logger.error("Invalid response format from users endpoint")
                return False
            
            # Find the user with matching email
            for user in users_data['resource']['resources']:
                if user.get('email') == email:
                    # Get specific user details
                    user_id = user.get('identifier')
                    response = self.session.get(
                        self._build_url(f'users/{user_id}'),
                        headers={'Accept': 'application/json'}
                    )
                    self._check_response_code(response, f'user details for ID {user_id}')
                    
                    user_data = response.json()
                    if 'resource' not in user_data:
                        return False
                    
                    system_role = user_data['resource'].get('systemRole')
                    return system_role == 'ROLE_ADMIN'
                
            self.logger.error(f"Email {email} not found in system")
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking email admin status: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Generate CSV file mapping samples to their NGS archive files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('-p', '--project', required=True,
                       help='The ID of the project to process')
    parser.add_argument('-e', '--email', required=True,
                       help='Email address to validate project access')
    
    # Optional arguments
    parser.add_argument('-o', '--output', default=os.getcwd(),
                       help='Directory to output the CSV file')
    parser.add_argument('-s', '--sample', action='append',
                       help='Specific sample ID to include (can be used multiple times)')
    parser.add_argument('--duplicate-handling', 
                       choices=[DuplicateHandling.FAIL, 
                               DuplicateHandling.IGNORE, 
                               DuplicateHandling.RENAME],
                       default=DuplicateHandling.FAIL,
                       help='How to handle duplicate files')
    
    # Authentication options
    parser.add_argument('-c', '--config',
                       help='Location of the config file')
    parser.add_argument('-b', '--baseURL',
                       help='Base URL for the NGS Archive REST API')
    parser.add_argument('--username',
                       help='Username for API requests')
    parser.add_argument('--password',
                       help='Password for API requests')
    parser.add_argument('--client-id',
                       help='OAuth2 client ID for API requests')
    parser.add_argument('--client-secret',
                       help='OAuth2 client secret for API requests')
    
    # Other options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Print verbose messages')
    parser.add_argument('--version', action='version',
                       version=f'%(prog)s {VERSION}')

    args = parser.parse_args()
    
    # Setup logger and linker
    logger = setup_logger(args.verbose)
    linker = IRIDALinker(logger)
    
    # Handle config file
    config = configparser.ConfigParser()
    config_file = args.config
    
    if not config_file:
        for loc in DEFAULT_CONFIG_LOCATIONS:
            if loc and os.path.exists(loc):
                config_file = loc
                logger.debug(f"Using configuration {loc}")
                break

    if config_file and os.path.exists(config_file):
        config.read(config_file)
        if not args.username:
            args.username = config.get('Settings', 'username', fallback=None)
        if not args.password:
            args.password = config.get('Settings', 'password', fallback=None)
        if not args.baseURL:
            args.baseURL = config.get('Settings', 'base_url', fallback=None)
        if not args.client_id:
            args.client_id = config.get('Settings', 'client_id', fallback="defaultLinker")
        if not args.client_secret:
            args.client_secret = config.get('Settings', 'client_secret', fallback="defaultLinkerSecret")

    # Get username/password if not provided
    if not args.username:
        args.username = input("Enter username: ")
    if not args.password:
        args.password = getpass.getpass("Enter password: ")

    # Main execution logic
    try:
        # Authenticate and validate
        if not args.baseURL:
            logger.error("Base URL is required. Provide it via --baseURL or config file")
            sys.exit(1)

        # Set client credentials before getting token
        linker.client_id = args.client_id or "defaultLinker"
        linker.client_secret = args.client_secret or "defaultLinkerSecret"

        token = linker.get_token(args.baseURL, args.username, args.password)
        linker.session.headers.update({'Authorization': f'Bearer {token}'})
        linker.check_server_status(args.baseURL)

        # Check if email has admin permissions
        is_email_admin = linker.check_email_admin_status(args.email)
        if not is_email_admin:
            logger.error(f"Email {args.email} does not have admin privileges")
            sys.exit(1)
        else:
            logger.debug(f"Email {args.email} has admin privileges - proceeding")

        # Generate CSV
        linker.generate_project_csv(args.project, args.output, args.sample)

    except requests.exceptions.ConnectionError:
        logger.error(f"Could not connect to {args.baseURL}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during API request: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 