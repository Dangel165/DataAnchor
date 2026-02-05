import os
import subprocess
import re
from datetime import datetime
import win32com.client
import pythoncom
import shutil

class VSSRecovery:
    def __init__(self):
        self.shadow_copies = []
        
    def list_shadow_copies(self):
        """섀도우 복사본 목록 가져오기"""
        shadows = []
        
        try:
            # vssadmin 명령어로 섀도우 복사본 목록 가져오기
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='cp949'  # Windows 한글 인코딩
            )
            
            if result.returncode != 0:
                return shadows
            
            output = result.stdout
            
            # 섀도우 복사본 정보 파싱
            shadow_blocks = output.split('섀도 복사본 ID:')
            
            for block in shadow_blocks[1:]:  # 첫 번째는 헤더
                shadow_info = {}
                
                # ID 추출
                id_match = re.search(r'\{([^}]+)\}', block)
                if id_match:
                    shadow_info['id'] = id_match.group(1)
                
                # 원본 볼륨 추출
                volume_match = re.search(r'원본 볼륨:\s*([A-Z]:\\)', block)
                if volume_match:
                    shadow_info['volume'] = volume_match.group(1)
                
                # 섀도우 복사본 볼륨 추출
                shadow_volume_match = re.search(r'섀도 복사본 볼륨:\s*(\\\\[^\s]+)', block)
                if shadow_volume_match:
                    shadow_info['shadow_volume'] = shadow_volume_match.group(1)
                
                # 생성 시간 추출
                time_match = re.search(r'생성 시간:\s*(.+)', block)
                if time_match:
                    shadow_info['created'] = time_match.group(1).strip()
                
                if 'id' in shadow_info and 'shadow_volume' in shadow_info:
                    shadows.append(shadow_info)
            
            self.shadow_copies = shadows
            return shadows
            
        except subprocess.TimeoutExpired:
            return shadows
        except Exception as e:
            print(f"섀도우 복사본 목록 가져오기 실패: {e}")
            return shadows
    
    def create_symbolic_link(self, shadow_volume, link_path):
        """섀도우 복사본에 대한 심볼릭 링크 생성"""
        try:
            # 기존 링크 삭제
            if os.path.exists(link_path):
                try:
                    os.rmdir(link_path)
                except:
                    pass
            
            # mklink 명령어로 심볼릭 링크 생성
            cmd = f'mklink /D "{link_path}" "{shadow_volume}\\"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                encoding='cp949'
            )
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"심볼릭 링크 생성 실패: {e}")
            return False
    
    def scan_shadow_copy(self, shadow_info, search_paths=None):
        """특정 섀도우 복사본 스캔"""
        files = []
        
        if not shadow_info or 'shadow_volume' not in shadow_info:
            return files
        
        shadow_volume = shadow_info['shadow_volume']
        link_path = "C:\\ShadowCopyTemp"
        
        try:
            # 심볼릭 링크 생성
            if not self.create_symbolic_link(shadow_volume, link_path):
                return files
            
            # 검색할 경로 설정
            if search_paths is None:
                search_paths = [
                    'Users',
                    'Documents and Settings'
                ]
            
            # 각 경로 스캔
            for search_path in search_paths:
                full_path = os.path.join(link_path, search_path)
                
                if not os.path.exists(full_path):
                    continue
                
                try:
                    for root, dirs, filenames in os.walk(full_path):
                        # 시스템 폴더 제외
                        dirs[:] = [d for d in dirs if not d.startswith('$') 
                                  and d.lower() not in ['appdata', 'temp', 'cache']]
                        
                        for filename in filenames:
                            try:
                                file_path = os.path.join(root, filename)
                                stat = os.stat(file_path)
                                
                                # 상대 경로 계산
                                relative_path = os.path.relpath(file_path, link_path)
                                original_path = os.path.join(
                                    shadow_info.get('volume', 'C:\\'),
                                    relative_path
                                )
                                
                                files.append({
                                    'name': filename,
                                    'size': stat.st_size,
                                    'type': os.path.splitext(filename)[1][1:].upper() or 'FILE',
                                    'modified': datetime.fromtimestamp(stat.st_mtime),
                                    'original_path': original_path,
                                    'shadow_path': file_path,
                                    'shadow_id': shadow_info.get('id', ''),
                                    'shadow_created': shadow_info.get('created', '')
                                })
                                
                            except Exception as e:
                                continue
                                
                except PermissionError:
                    continue
            
        except Exception as e:
            print(f"섀도우 복사본 스캔 실패: {e}")
        
        finally:
            # 심볼릭 링크 정리
            try:
                if os.path.exists(link_path):
                    os.rmdir(link_path)
            except:
                pass
        
        return files

    
    def recover_file_from_shadow(self, shadow_path, destination):
        """섀도우 복사본에서 파일 복구"""
        try:
            # 파일 복사
            shutil.copy2(shadow_path, destination)
            return True
        except Exception as e:
            print(f"파일 복구 실패: {e}")
            return False
    
    def find_file_in_shadows(self, filename, max_shadows=3):
        """모든 섀도우 복사본에서 특정 파일 찾기"""
        found_files = []
        
        shadows = self.list_shadow_copies()
        
        for shadow in shadows[:max_shadows]:
            shadow_volume = shadow.get('shadow_volume', '')
            link_path = "C:\\ShadowCopyTemp"
            
            try:
                if not self.create_symbolic_link(shadow_volume, link_path):
                    continue
                
                # 파일 검색
                for root, dirs, files in os.walk(link_path):
                    if filename in files:
                        file_path = os.path.join(root, filename)
                        
                        try:
                            stat = os.stat(file_path)
                            
                            found_files.append({
                                'name': filename,
                                'path': file_path,
                                'size': stat.st_size,
                                'modified': datetime.fromtimestamp(stat.st_mtime),
                                'shadow_id': shadow.get('id', ''),
                                'shadow_created': shadow.get('created', '')
                            })
                        except:
                            continue
                
            except Exception as e:
                continue
            
            finally:
                try:
                    if os.path.exists(link_path):
                        os.rmdir(link_path)
                except:
                    pass
        
        return found_files
    
    def get_shadow_copy_info(self):
        """섀도우 복사본 정보 요약"""
        shadows = self.list_shadow_copies()
        
        info = {
            'count': len(shadows),
            'shadows': []
        }
        
        for shadow in shadows:
            info['shadows'].append({
                'volume': shadow.get('volume', 'Unknown'),
                'created': shadow.get('created', 'Unknown'),
                'id': shadow.get('id', 'Unknown')[:8] + '...'  # ID 축약
            })
        
        return info


class VSSRecoveryWMI:
    """WMI를 사용한 VSS 복구 (대체 방법)"""
    
    def __init__(self):
        self.wmi = None
        
    def initialize(self):
        """WMI 초기화"""
        try:
            pythoncom.CoInitialize()
            self.wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            return True
        except Exception as e:
            print(f"WMI 초기화 실패: {e}")
            return False
    
    def list_shadow_copies_wmi(self):
        """WMI로 섀도우 복사본 목록 가져오기"""
        shadows = []
        
        try:
            if not self.wmi:
                if not self.initialize():
                    return shadows
            
            service = self.wmi.ConnectServer(".", "root\\cimv2")
            
            # Win32_ShadowCopy 쿼리
            shadow_copies = service.ExecQuery("SELECT * FROM Win32_ShadowCopy")
            
            for shadow in shadow_copies:
                shadows.append({
                    'id': shadow.ID,
                    'volume': shadow.VolumeName,
                    'device': shadow.DeviceObject,
                    'created': shadow.InstallDate,
                    'count': shadow.Count
                })
            
            return shadows
            
        except Exception as e:
            print(f"WMI 섀도우 복사본 조회 실패: {e}")
            return shadows
        
        finally:
            try:
                pythoncom.CoUninitialize()
            except:
                pass


def test_vss_recovery():
    """VSS 복구 테스트"""
    print("=== VSS 복구 테스트 ===\n")
    
    vss = VSSRecovery()
    
    print("1. 섀도우 복사본 목록 가져오기...")
    shadows = vss.list_shadow_copies()
    
    if not shadows:
        print("   ❌ 섀도우 복사본이 없습니다.")
        print("   💡 시스템 복원 기능을 활성화하세요.")
        return
    
    print(f"   ✅ {len(shadows)}개의 섀도우 복사본 발견\n")
    
    for idx, shadow in enumerate(shadows, 1):
        print(f"   섀도우 #{idx}")
        print(f"   - 볼륨: {shadow.get('volume', 'N/A')}")
        print(f"   - 생성: {shadow.get('created', 'N/A')}")
        print(f"   - ID: {shadow.get('id', 'N/A')[:16]}...")
        print()
    
    print("2. 섀도우 복사본 정보 요약...")
    info = vss.get_shadow_copy_info()
    print(f"   총 {info['count']}개의 복원 지점\n")
    
    print("✅ VSS 복구 모듈이 정상적으로 작동합니다!")


if __name__ == "__main__":
    test_vss_recovery()
