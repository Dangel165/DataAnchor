import os
import sys
import ctypes
import struct
import subprocess
from datetime import datetime

class PartitionRecovery:
    """파티션 복구 클래스"""
    
    def __init__(self):
        self.partition_types = {
            0x00: "Empty",
            0x01: "FAT12",
            0x04: "FAT16 <32MB",
            0x05: "Extended",
            0x06: "FAT16",
            0x07: "NTFS/exFAT",
            0x0B: "FAT32",
            0x0C: "FAT32 LBA",
            0x0E: "FAT16 LBA",
            0x0F: "Extended LBA",
            0x82: "Linux Swap",
            0x83: "Linux",
            0x85: "Linux Extended",
            0x8E: "Linux LVM",
            0xEE: "GPT Protective",
            0xEF: "EFI System"
        }
    
    def is_admin(self):
        """관리자 권한 확인"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def list_physical_disks(self):
        """물리 디스크 목록"""
        disks = []
        
        try:
            print("디스크 목록 조회 중...")
            # diskpart 사용
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle | ConvertTo-Json'],
                capture_output=True, text=True, timeout=10
            )
            
            print(f"Return code: {result.returncode}")
            print(f"Stdout: {result.stdout[:200]}")
            print(f"Stderr: {result.stderr[:200]}")
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                disk_info = json.loads(result.stdout)
                
                if isinstance(disk_info, dict):
                    disk_info = [disk_info]
                
                for disk in disk_info:
                    disks.append({
                        'number': disk.get('Number', 0),
                        'name': disk.get('FriendlyName', 'Unknown'),
                        'size': self.format_size(disk.get('Size', 0)),
                        'style': disk.get('PartitionStyle', 'Unknown')
                    })
                    
                print(f"발견된 디스크: {len(disks)}개")
            else:
                print("PowerShell 명령 실패 또는 출력 없음")
                
        except Exception as e:
            print(f"디스크 목록 오류: {e}")
            import traceback
            traceback.print_exc()
        
        return disks
    
    def scan_disk_for_partitions(self, disk_number):
        """디스크에서 파티션 스캔 (MBR/GPT)"""
        partitions = []
        
        try:
            # 현재 파티션 목록
            current_partitions = self.get_current_partitions(disk_number)
            partitions.extend(current_partitions)
            
            # 삭제된 파티션 스캔 (MBR 시그니처 검색)
            deleted_partitions = self.scan_deleted_partitions(disk_number)
            partitions.extend(deleted_partitions)
            
        except Exception as e:
            print(f"파티션 스캔 오류: {e}")
        
        return partitions
    
    def get_current_partitions(self, disk_number):
        """현재 파티션 목록"""
        partitions = []
        
        try:
            print(f"디스크 {disk_number} 파티션 조회 중...")
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Get-Partition -DiskNumber {disk_number} | Select-Object PartitionNumber, DriveLetter, Size, Type | ConvertTo-Json'],
                capture_output=True, text=True, timeout=10
            )
            
            print(f"Return code: {result.returncode}")
            print(f"Stdout: {result.stdout[:200]}")
            print(f"Stderr: {result.stderr[:200]}")
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                partition_info = json.loads(result.stdout)
                
                if isinstance(partition_info, dict):
                    partition_info = [partition_info]
                
                for part in partition_info:
                    drive_letter = part.get('DriveLetter', '')
                    if drive_letter:
                        drive_letter = f"{drive_letter}:"
                    
                    partitions.append({
                        'disk': disk_number,
                        'partition': part.get('PartitionNumber', 0),
                        'drive_letter': drive_letter,
                        'size': self.format_size(part.get('Size', 0)),
                        'type': part.get('Type', 'Unknown'),
                        'status': '정상',
                        'recoverable': False
                    })
                    
                print(f"발견된 파티션: {len(partitions)}개")
            else:
                print("파티션 정보 없음 또는 오류")
                
        except Exception as e:
            print(f"현재 파티션 목록 오류: {e}")
            import traceback
            traceback.print_exc()
        
        return partitions
    
    def scan_deleted_partitions(self, disk_number):
        """삭제된 파티션 스캔 (시그니처 기반)"""
        partitions = []
        
        # 관리자 권한 필요
        if not self.is_admin():
            return partitions
        
        try:
            # 디스크 섹터 직접 읽기
            deleted = self.scan_disk_sectors(disk_number)
            partitions.extend(deleted)
            
            # Windows API를 통한 기본 검색
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Get-Volume | Where-Object {{$_.DriveLetter -eq $null}} | Select-Object FileSystemLabel, Size, FileSystem | ConvertTo-Json'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    volume_info = json.loads(result.stdout)
                    
                    if isinstance(volume_info, dict):
                        volume_info = [volume_info]
                    
                    for vol in volume_info:
                        if vol.get('Size', 0) > 0:
                            partitions.append({
                                'disk': disk_number,
                                'partition': '?',
                                'drive_letter': '없음',
                                'size': self.format_size(vol.get('Size', 0)),
                                'type': vol.get('FileSystem', 'Unknown'),
                                'label': vol.get('FileSystemLabel', ''),
                                'status': '드라이브 문자 없음',
                                'recoverable': True
                            })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"삭제된 파티션 스캔 오류: {e}")
        
        return partitions
    
    def scan_disk_sectors(self, disk_number):
        """디스크 섹터를 직접 읽어 파일시스템 시그니처 검색"""
        found_partitions = []
        
        if not self.is_admin():
            return found_partitions
        
        try:
            # 물리 디스크 열기
            disk_path = f"\\\\.\\PhysicalDrive{disk_number}"
            
            print(f"디스크 섹터 스캔 시작: {disk_path}")
            
            # Windows API로 디스크 열기
            import ctypes
            from ctypes import wintypes
            
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 0x80
            
            kernel32 = ctypes.windll.kernel32
            
            handle = kernel32.CreateFileW(
                disk_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )
            
            if handle == -1:
                print(f"디스크 열기 실패: {disk_path}")
                return found_partitions
            
            try:
                # 섹터 크기 (일반적으로 512 바이트)
                sector_size = 512
                buffer_size = sector_size * 8  # 4KB씩 읽기
                buffer = ctypes.create_string_buffer(buffer_size)
                bytes_read = wintypes.DWORD()
                
                # 디스크 크기 확인 (최대 100GB만 스캔)
                max_sectors = (100 * 1024 * 1024 * 1024) // sector_size
                scan_sectors = min(max_sectors, 1000000)  # 최대 100만 섹터
                
                print(f"스캔할 섹터 수: {scan_sectors}")
                
                # 섹터 스캔 (샘플링: 매 1000번째 섹터)
                for sector in range(0, scan_sectors, 1000):
                    # 섹터 위치로 이동
                    offset = sector * sector_size
                    
                    # SetFilePointer
                    low = offset & 0xFFFFFFFF
                    high = (offset >> 32) & 0xFFFFFFFF
                    
                    kernel32.SetFilePointer(handle, low, ctypes.byref(ctypes.c_long(high)), 0)
                    
                    # 섹터 읽기
                    if kernel32.ReadFile(handle, buffer, buffer_size, ctypes.byref(bytes_read), None):
                        data = buffer.raw[:bytes_read.value]
                        
                        # 파일시스템 시그니처 검색
                        fs_type = self.detect_filesystem_signature(data)
                        
                        if fs_type:
                            # 파티션 크기 추정 (간단한 휴리스틱)
                            estimated_size = self.estimate_partition_size(data, fs_type)
                            
                            found_partitions.append({
                                'disk': disk_number,
                                'partition': f'복구{len(found_partitions)+1}',
                                'drive_letter': '없음',
                                'size': self.format_size(estimated_size),
                                'type': fs_type,
                                'status': f'삭제됨 (섹터 {sector})',
                                'recoverable': True,
                                'sector_offset': sector
                            })
                            
                            print(f"발견: {fs_type} at sector {sector}")
                            
                            # 최대 10개까지만
                            if len(found_partitions) >= 10:
                                break
                
            finally:
                kernel32.CloseHandle(handle)
                
        except Exception as e:
            print(f"섹터 스캔 오류: {e}")
            import traceback
            traceback.print_exc()
        
        return found_partitions
    
    def detect_filesystem_signature(self, data):
        """파일시스템 시그니처 감지"""
        if len(data) < 1100:
            return None
        
        try:
            # NTFS 시그니처: "NTFS    " at offset 3
            if data[3:11] == b'NTFS    ':
                return 'NTFS'
            
            # FAT32 시그니처: "FAT32   " at offset 82
            if len(data) > 90 and data[82:90] == b'FAT32   ':
                return 'FAT32'
            
            # FAT16 시그니처: "FAT16   " at offset 54
            if len(data) > 62 and data[54:62] == b'FAT16   ':
                return 'FAT16'
            
            # FAT12 시그니처: "FAT12   " at offset 54
            if len(data) > 62 and data[54:62] == b'FAT12   ':
                return 'FAT12'
            
            # exFAT 시그니처: "EXFAT   " at offset 3
            if data[3:11] == b'EXFAT   ':
                return 'exFAT'
            
            # EXT2/3/4 시그니처: 0x53EF at offset 1080 (magic number)
            if len(data) > 1082:
                if data[1080:1082] == b'\x53\xEF':
                    return 'EXT2/3/4'
            
            # ReFS 시그니처
            if data[0:4] == b'\x00\x00\x00ReFS':
                return 'ReFS'
            
        except Exception as e:
            print(f"시그니처 감지 오류: {e}")
        
        return None
    
    def estimate_partition_size(self, data, fs_type):
        """파티션 크기 추정"""
        try:
            if fs_type == 'NTFS':
                # NTFS: 섹터 수는 offset 0x28에 8바이트
                if len(data) >= 0x30:
                    import struct
                    total_sectors = struct.unpack('<Q', data[0x28:0x30])[0]
                    return total_sectors * 512
            
            elif fs_type == 'FAT32':
                # FAT32: 섹터 수는 offset 0x20에 4바이트
                if len(data) >= 0x24:
                    import struct
                    total_sectors = struct.unpack('<I', data[0x20:0x24])[0]
                    return total_sectors * 512
            
            elif fs_type in ['FAT16', 'FAT12']:
                # FAT16/12: 섹터 수는 offset 0x13에 2바이트
                if len(data) >= 0x15:
                    import struct
                    total_sectors = struct.unpack('<H', data[0x13:0x15])[0]
                    if total_sectors == 0:
                        # 큰 파티션은 offset 0x20
                        total_sectors = struct.unpack('<I', data[0x20:0x24])[0]
                    return total_sectors * 512
            
            elif fs_type == 'EXT2/3/4':
                # EXT: 블록 수는 offset 1028에 4바이트
                if len(data) >= 1032:
                    import struct
                    total_blocks = struct.unpack('<I', data[1028:1032])[0]
                    block_size = 1024 << struct.unpack('<I', data[1048:1052])[0]
                    return total_blocks * block_size
            
        except Exception as e:
            print(f"크기 추정 오류: {e}")
        
        # 기본값: 10GB
        return 10 * 1024 * 1024 * 1024
    
    def assign_drive_letter(self, disk_number, partition_number):
        """드라이브 문자 할당"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # 사용 가능한 드라이브 문자 찾기
            used_letters = set()
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if os.path.exists(f"{letter}:\\"):
                    used_letters.add(letter)
            
            available_letters = [l for l in 'DEFGHIJKLMNOPQRSTUVWXYZ' if l not in used_letters]
            
            if not available_letters:
                return False, "사용 가능한 드라이브 문자가 없습니다."
            
            new_letter = available_letters[0]
            
            # PowerShell로 드라이브 문자 할당
            cmd = f'Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} | Set-Partition -NewDriveLetter {new_letter}'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                return True, f"드라이브 문자 {new_letter}: 할당 완료"
            else:
                return False, f"할당 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def recover_partition_table(self, disk_number):
        """파티션 테이블 복구 (TestDisk 스타일)"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # 실제 구현에서는 TestDisk 같은 도구 사용
            # 여기서는 기본 복구 시도
            
            # 1. 디스크 오류 검사
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Repair-Volume -DiskNumber {disk_number} -Scan'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "파티션 테이블 스캔 완료"
            else:
                return False, "복구 실패"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def backup_partition_table(self, disk_number, backup_path):
        """파티션 테이블 백업"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # MBR/GPT 백업
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_path, f"partition_backup_disk{disk_number}_{timestamp}.txt")
            
            # 파티션 정보 저장
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Get-Partition -DiskNumber {disk_number} | Out-File -FilePath "{backup_file}"'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and os.path.exists(backup_file):
                return True, f"백업 완료: {backup_file}"
            else:
                return False, "백업 실패"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def check_filesystem(self, drive_letter):
        """파일시스템 검사 및 복구"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # chkdsk 실행
            result = subprocess.run(
                ['chkdsk', f"{drive_letter}:", '/F', '/R'],
                capture_output=True, text=True, timeout=300
            )
            
            if result.returncode == 0:
                return True, "파일시스템 검사 완료"
            else:
                return False, f"검사 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def format_size(self, size_bytes):
        """파일 크기 포맷"""
        try:
            size_bytes = int(size_bytes)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.1f} PB"
        except:
            return "0 B"
    
    def get_disk_info(self, disk_number):
        """디스크 상세 정보"""
        info = {
            'number': disk_number,
            'name': 'Unknown',
            'size': '0 B',
            'style': 'Unknown',
            'status': 'Unknown',
            'partitions': []
        }
        
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Get-Disk -Number {disk_number} | Select-Object Number, FriendlyName, Size, PartitionStyle, OperationalStatus | ConvertTo-Json'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                import json
                disk_data = json.loads(result.stdout)
                
                info['name'] = disk_data.get('FriendlyName', 'Unknown')
                info['size'] = self.format_size(disk_data.get('Size', 0))
                info['style'] = disk_data.get('PartitionStyle', 'Unknown')
                info['status'] = disk_data.get('OperationalStatus', 'Unknown')
                
        except Exception as e:
            print(f"디스크 정보 오류: {e}")
        
        return info
    
    def resize_partition(self, disk_number, partition_number, new_size_gb):
        """파티션 크기 조정"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # 새 크기를 바이트로 변환
            new_size_bytes = int(new_size_gb * 1024 * 1024 * 1024)
            
            # PowerShell로 파티션 크기 조정
            cmd = f'Resize-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -Size {new_size_bytes}'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, f"파티션 크기가 {new_size_gb}GB로 조정되었습니다."
            else:
                return False, f"크기 조정 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def get_partition_max_size(self, disk_number, partition_number):
        """파티션 최대 확장 가능 크기"""
        try:
            cmd = f'(Get-PartitionSupportedSize -DiskNumber {disk_number} -PartitionNumber {partition_number}).SizeMax'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                max_bytes = int(result.stdout.strip())
                return max_bytes / (1024**3)  # GB로 변환
            
        except Exception as e:
            print(f"최대 크기 확인 오류: {e}")
        
        return 0
    
    def create_partition(self, disk_number, size_gb=None, drive_letter=None):
        """새 파티션 생성"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # 크기 지정
            size_param = ""
            if size_gb:
                size_bytes = int(size_gb * 1024 * 1024 * 1024)
                size_param = f"-Size {size_bytes}"
            else:
                size_param = "-UseMaximumSize"
            
            # 드라이브 문자 지정
            letter_param = ""
            if drive_letter:
                letter_param = f"-DriveLetter {drive_letter}"
            else:
                letter_param = "-AssignDriveLetter"
            
            cmd = f'New-Partition -DiskNumber {disk_number} {size_param} {letter_param}'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "새 파티션이 생성되었습니다."
            else:
                return False, f"생성 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def delete_partition(self, disk_number, partition_number):
        """파티션 삭제"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            cmd = f'Remove-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -Confirm:$false'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "파티션이 삭제되었습니다."
            else:
                return False, f"삭제 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def format_partition(self, disk_number, partition_number, filesystem='NTFS', label=''):
        """파티션 포맷"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            label_param = f"-NewFileSystemLabel '{label}'" if label else ""
            
            cmd = f'Format-Volume -Partition (Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number}) -FileSystem {filesystem} {label_param} -Confirm:$false'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                return True, f"파티션이 {filesystem}로 포맷되었습니다."
            else:
                return False, f"포맷 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def convert_to_gpt(self, disk_number):
        """MBR을 GPT로 변환"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # 디스크가 비어있어야 함
            cmd = f'Set-Disk -Number {disk_number} -PartitionStyle GPT'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "디스크가 GPT로 변환되었습니다."
            else:
                return False, f"변환 실패: {result.stderr}\n\n디스크에 파티션이 있으면 변환할 수 없습니다."
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def convert_to_mbr(self, disk_number):
        """GPT를 MBR로 변환"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            cmd = f'Set-Disk -Number {disk_number} -PartitionStyle MBR'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "디스크가 MBR로 변환되었습니다."
            else:
                return False, f"변환 실패: {result.stderr}\n\n디스크에 파티션이 있으면 변환할 수 없습니다."
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def initialize_disk(self, disk_number, partition_style='GPT'):
        """디스크 초기화"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            cmd = f'Initialize-Disk -Number {disk_number} -PartitionStyle {partition_style} -Confirm:$false'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, f"디스크가 {partition_style}로 초기화되었습니다."
            else:
                return False, f"초기화 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"
    
    def get_unallocated_space(self, disk_number):
        """할당되지 않은 공간 확인"""
        try:
            # 디스크 전체 크기
            cmd_total = f'(Get-Disk -Number {disk_number}).Size'
            result_total = subprocess.run(
                ['powershell', '-Command', cmd_total],
                capture_output=True, text=True, timeout=10
            )
            
            if result_total.returncode != 0:
                return 0
            
            total_size = int(result_total.stdout.strip())
            
            # 파티션 크기 합계
            cmd_used = f'(Get-Partition -DiskNumber {disk_number} | Measure-Object -Property Size -Sum).Sum'
            result_used = subprocess.run(
                ['powershell', '-Command', cmd_used],
                capture_output=True, text=True, timeout=10
            )
            
            used_size = 0
            if result_used.returncode == 0 and result_used.stdout.strip():
                used_size = int(result_used.stdout.strip())
            
            unallocated = total_size - used_size
            return unallocated / (1024**3)  # GB로 변환
            
        except Exception as e:
            print(f"미할당 공간 확인 오류: {e}")
            return 0
    
    def repair_gpt(self, disk_number):
        """GPT 파티션 테이블 복구"""
        if not self.is_admin():
            return False, "관리자 권한이 필요합니다."
        
        try:
            # GPT 백업에서 복구 시도
            cmd = f'Repair-Volume -DiskNumber {disk_number}'
            
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                return True, "GPT 파티션 테이블이 복구되었습니다."
            else:
                # diskpart 사용
                diskpart_script = f"""
select disk {disk_number}
clean
convert gpt
"""
                result2 = subprocess.run(
                    ['diskpart'],
                    input=diskpart_script,
                    capture_output=True, text=True, timeout=30
                )
                
                if "successfully" in result2.stdout.lower():
                    return True, "GPT로 재초기화되었습니다. (데이터 손실)"
                else:
                    return False, f"복구 실패: {result.stderr}"
                
        except Exception as e:
            return False, f"오류: {str(e)}"

if __name__ == "__main__":
    # 테스트
    recovery = PartitionRecovery()
    
    if not recovery.is_admin():
        print("⚠️ 관리자 권한으로 실행하세요.")
    
    print("물리 디스크 목록:")
    disks = recovery.list_physical_disks()
    for disk in disks:
        print(f"  디스크 {disk['number']}: {disk['name']} ({disk['size']})")
