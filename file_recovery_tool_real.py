"""
DataAnchor - 데이터 복구 도구
Windows 휴지통, 섀도우 복사본, 임시 파일에서 삭제된 파일 복구
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import shutil
import winreg
from datetime import datetime
import subprocess
import ctypes
from pathlib import Path
import json

class DataAnchor:
    def __init__(self, root):
        self.root = root
        self.root.title("DataAnchor")
        self.root.geometry("1200x1000")
        self.root.resizable(True, True)
        
        self.scanning = False
        self.recovered_files = []
        
        # 복구 소스
        self.recovery_sources = {
            'recycle_bin': True,
            'shadow_copy': True,
            'temp_files': True,
            'recent_files': True
        }
        
        # 파티션 복구 모듈
        try:
            from partition_recovery import PartitionRecovery
            self.partition_recovery = PartitionRecovery()
        except ImportError:
            self.partition_recovery = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """UI 구성"""
        # 상단 프레임
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        title_frame = ttk.Frame(top_frame)
        title_frame.pack(fill=tk.X)
        
        ttk.Label(title_frame, text="DataAnchor", 
                 font=("맑은 고딕", 16, "bold")).pack(side=tk.LEFT)
        ttk.Label(title_frame, text="v1.0 by Dangel", 
                 font=("맑은 고딕", 8), foreground="gray").pack(side=tk.LEFT, padx=10)
        
        ttk.Button(title_frame, text="도움말", command=self.show_help, 
                  width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(title_frame, text="정보", command=self.show_about, 
                  width=10).pack(side=tk.RIGHT)
        
        ttk.Label(top_frame, text="휴지통, 섀도우 복사본, 임시 파일, QR 코드에서 삭제된 파일 복구", 
                 font=("맑은 고딕", 9)).pack()
        
        # 드라이브 선택 프레임
        drive_frame = ttk.LabelFrame(self.root, text="스캔 드라이브 선택", padding="10")
        drive_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(drive_frame, text="드라이브:").grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(drive_frame, textvariable=self.drive_var, 
                                        width=15, state="readonly")
        self.drive_combo.grid(row=0, column=1, padx=5)
        self.drive_combo['values'] = self.get_available_drives()
        if self.drive_combo['values']:
            self.drive_combo.current(0)
        
        
        # 복구 소스 선택 프레임
        source_frame = ttk.LabelFrame(self.root, text="복구 소스 선택", padding="10")
        source_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.recycle_var = tk.BooleanVar(value=True)
        self.shadow_var = tk.BooleanVar(value=True)
        self.temp_var = tk.BooleanVar(value=True)
        self.recent_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(source_frame, text="휴지통 ($Recycle.Bin)", 
                       variable=self.recycle_var).grid(row=0, column=0, sticky=tk.W, padx=10)
        ttk.Checkbutton(source_frame, text="섀도우 복사본 (VSS)", 
                       variable=self.shadow_var).grid(row=0, column=1, sticky=tk.W, padx=10)
        ttk.Checkbutton(source_frame, text="임시 파일", 
                       variable=self.temp_var).grid(row=0, column=2, sticky=tk.W, padx=10)
        ttk.Checkbutton(source_frame, text="최근 파일", 
                       variable=self.recent_var).grid(row=0, column=3, sticky=tk.W, padx=10)
        
        # 검색 옵션 프레임
        search_frame = ttk.LabelFrame(self.root, text="검색 옵션", padding="10")
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(search_frame, text="파일명 검색:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).grid(row=0, column=1, padx=5)
        
        ttk.Label(search_frame, text="파일 형식:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.file_type_var = tk.StringVar(value="모든 파일")
        file_types = ["모든 파일", "문서", "이미지", "비디오", "압축", "기타"]
        ttk.Combobox(search_frame, textvariable=self.file_type_var, values=file_types,
                    width=15, state="readonly").grid(row=0, column=3, padx=5)
        
        # 버튼 프레임
        button_frame = ttk.Frame(search_frame)
        button_frame.grid(row=0, column=4, padx=10)
        
        self.scan_btn = ttk.Button(button_frame, text="스캔 시작", 
                                   command=self.start_scan, width=12)
        self.scan_btn.pack(side=tk.LEFT, padx=2)
        
        self.stop_btn = ttk.Button(button_frame, text="중지", 
                                   command=self.stop_scan, width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        # 파티션 복구 버튼 추가
        ttk.Button(button_frame, text="파티션 복구", 
                  command=self.open_partition_recovery, width=12).pack(side=tk.LEFT, padx=2)
        
        # 진행 상황 프레임
        progress_frame = ttk.LabelFrame(self.root, text="스캔 진행 상황", padding="10")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                           maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="대기 중...", 
                                     font=("맑은 고딕", 9))
        self.status_label.pack()
        
        # 결과 프레임
        result_frame = ttk.LabelFrame(self.root, text="복구 가능한 파일", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 트리뷰 생성
        columns = ("파일명", "크기", "형식", "삭제 시간", "원본 경로", "복구 소스")
        self.tree = ttk.Treeview(result_frame, columns=columns, show="tree headings", 
                                height=15, selectmode="extended")
        
        self.tree.heading("#0", text="선택")
        self.tree.column("#0", width=50)
        
        widths = {"파일명": 200, "크기": 80, "형식": 60, "삭제 시간": 130, 
                 "원본 경로": 250, "복구 소스": 100}
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=widths.get(col, 100))
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 하단 버튼 프레임
        bottom_frame = ttk.Frame(self.root, padding="10")
        bottom_frame.pack(fill=tk.X)
        
        ttk.Button(bottom_frame, text="전체 선택", 
                  command=self.select_all, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="선택 해제", 
                  command=self.deselect_all, width=12).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(bottom_frame, text="QR 코드 복구", 
                  command=self.recover_qr_code, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(bottom_frame, text="목록 내보내기", 
                  command=self.export_list, width=15).pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom_frame, text="선택 파일 복구", 
                  command=self.recover_files, width=15).pack(side=tk.RIGHT, padx=5)
        
        self.stats_label = ttk.Label(bottom_frame, text="발견된 파일: 0개", 
                                    font=("맑은 고딕", 9))
        self.stats_label.pack(side=tk.LEFT, padx=20)

    def start_scan(self):
        """스캔 시작"""
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.tree.delete(*self.tree.get_children())
        self.recovered_files = []
        
        scan_thread = threading.Thread(target=self.scan_all_sources, daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """스캔 중지"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="스캔이 중지되었습니다.")
    
    def scan_all_sources(self):
        """모든 소스 스캔"""
        all_files = []
        
        if self.recycle_var.get():
            self.status_label.config(text="휴지통 스캔 중...")
            all_files.extend(self.scan_recycle_bin())
        
        if self.shadow_var.get() and self.scanning:
            self.status_label.config(text="섀도우 복사본 스캔 중...")
            all_files.extend(self.scan_shadow_copies())
        
        if self.temp_var.get() and self.scanning:
            self.status_label.config(text="임시 파일 스캔 중...")
            all_files.extend(self.scan_temp_files())
        
        if self.recent_var.get() and self.scanning:
            self.status_label.config(text="최근 파일 스캔 중...")
            all_files.extend(self.scan_recent_files())
        
        # 필터링
        filtered_files = self.filter_files(all_files)
        
        # 결과 표시 (최대 500개로 제한)
        max_display = 500
        total = min(len(filtered_files), max_display)
        
        if len(filtered_files) > max_display:
            self.status_label.config(text=f"⚠️ {len(filtered_files)}개 발견, 상위 {max_display}개만 표시")
        
        # 배치 처리로 UI 업데이트 최소화
        batch_size = 50
        for idx, file_info in enumerate(filtered_files[:max_display]):
            if not self.scanning:
                break
            
            self.tree.insert("", tk.END, values=(
                file_info['name'],
                file_info['size'],
                file_info['type'],
                file_info['deleted_time'],
                file_info['original_path'],
                file_info['source']
            ))
            
            self.recovered_files.append(file_info)
            
            # 배치마다 한 번만 UI 업데이트
            if (idx + 1) % batch_size == 0 or idx == total - 1:
                progress = (idx + 1) / total * 100
                self.progress_var.set(progress)
                self.status_label.config(text=f"표시 중... {idx + 1}/{total}")
                self.root.update_idletasks()
        
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        total_found = len(self.recovered_files)
        total_scanned = len(filtered_files)
        
        if total_scanned > max_display:
            self.status_label.config(text=f"스캔 완료! {total_scanned}개 발견 (상위 {max_display}개 표시)")
        else:
            self.status_label.config(text=f"스캔 완료! {total_found}개 파일 발견")
        
        self.stats_label.config(text=f"발견된 파일: {total_scanned}개 (표시: {total_found}개)")
        
        if self.scanning and total_found > 0:
            msg = f"{total_scanned}개의 복구 가능한 파일을 발견했습니다."
            if total_scanned > max_display:
                msg += f"\n\n⚠️ 파일이 너무 많아 상위 {max_display}개만 표시됩니다.\n"
                msg += "파일 형식 필터나 파일명 검색을 사용하여 범위를 좁히세요."
            messagebox.showinfo("스캔 완료", msg)

    def scan_recycle_bin(self):
        """휴지통 스캔 (선택된 드라이브만)"""
        files = []
        
        # 선택된 드라이브만 스캔
        selected_drive = self.drive_var.get()
        drives_to_scan = [selected_drive + "\\"] if selected_drive else self.get_drives()
        
        for drive in drives_to_scan:
            if not self.scanning:
                return files
                
            recycle_path = os.path.join(drive, "$Recycle.Bin")
            
            if not os.path.exists(recycle_path):
                continue
            
            try:
                for root, dirs, filenames in os.walk(recycle_path):
                    for filename in filenames:
                        if not self.scanning:
                            return files
                        
                        if filename.startswith('$R'):  # 실제 파일
                            file_path = os.path.join(root, filename)
                            
                            try:
                                stat = os.stat(file_path)
                                
                                # 원본 파일명 찾기
                                info_file = file_path.replace('$R', '$I')
                                original_name = self.get_original_filename(info_file, filename)
                                
                                files.append({
                                    'name': original_name,
                                    'size': self.format_size(stat.st_size),
                                    'type': os.path.splitext(original_name)[1][1:].upper() or 'FILE',
                                    'deleted_time': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                    'original_path': file_path,
                                    'source': '휴지통',
                                    'actual_path': file_path
                                })
                            except Exception as e:
                                continue
            except PermissionError:
                continue
        
        return files
    
    def get_original_filename(self, info_file, fallback):
        """원본 파일명 가져오기"""
        try:
            if os.path.exists(info_file):
                with open(info_file, 'rb') as f:
                    f.seek(24)  # 파일명 위치
                    name_bytes = f.read(520)
                    original_name = name_bytes.decode('utf-16-le').split('\x00')[0]
                    if original_name:
                        return os.path.basename(original_name)
        except:
            pass
        return fallback.replace('$R', '')

    def scan_shadow_copies(self):
        """섀도우 복사본 스캔 (VSS 실제 구현 - 최적화)"""
        files = []
        max_files = 100  # 최대 100개로 제한
        
        try:
            from vss_recovery import VSSRecovery
            
            vss = VSSRecovery()
            shadows = vss.list_shadow_copies()
            
            if not shadows:
                return files
            
            # 최대 2개의 섀도우 복사본만 스캔 (성능 고려)
            for shadow in shadows[:2]:
                if not self.scanning or len(files) >= max_files:
                    break
                
                self.status_label.config(
                    text=f"섀도우 복사본 스캔 중... ({shadow.get('created', 'Unknown')[:10]})"
                )
                self.root.update_idletasks()
                
                # 주요 사용자 폴더만 스캔
                search_paths = ['Users']
                shadow_files = vss.scan_shadow_copy(shadow, search_paths)
                
                # 파일 정보 변환
                for file_info in shadow_files:
                    if not self.scanning or len(files) >= max_files:
                        break
                    
                    files.append({
                        'name': file_info['name'],
                        'size': self.format_size(file_info['size']),
                        'type': file_info['type'],
                        'deleted_time': file_info['modified'].strftime("%Y-%m-%d %H:%M:%S"),
                        'original_path': file_info['original_path'],
                        'source': f"섀도우복사본 ({shadow.get('created', '')[:10]})",
                        'actual_path': file_info['shadow_path']
                    })
                    
        except ImportError:
            pass
        except Exception as e:
            print(f"섀도우 복사본 스캔 오류: {e}")
        
        return files

    def scan_temp_files(self):
        """임시 파일 스캔 (최적화)"""
        files = []
        max_files = 200  # 최대 200개로 제한
        
        temp_paths = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
        ]
        
        for temp_path in temp_paths:
            if not temp_path or not os.path.exists(temp_path) or len(files) >= max_files:
                continue
            
            try:
                # 최대 깊이 1로 제한 (하위 폴더 탐색 안 함)
                for filename in os.listdir(temp_path):
                    if not self.scanning or len(files) >= max_files:
                        break
                    
                    file_path = os.path.join(temp_path, filename)
                    
                    if not os.path.isfile(file_path):
                        continue
                    
                    try:
                        stat = os.stat(file_path)
                        
                        # 최근 7일 이내 파일만
                        age_days = (datetime.now().timestamp() - stat.st_mtime) / 86400
                        if age_days > 7:
                            continue
                        
                        # 너무 작거나 큰 파일 제외
                        if stat.st_size < 1024 or stat.st_size > 100 * 1024 * 1024:
                            continue
                        
                        files.append({
                            'name': filename,
                            'size': self.format_size(stat.st_size),
                            'type': os.path.splitext(filename)[1][1:].upper() or 'FILE',
                            'deleted_time': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            'original_path': file_path,
                            'source': '임시파일',
                            'actual_path': file_path
                        })
                    except:
                        continue
            except PermissionError:
                continue
        
        return files

    def scan_recent_files(self):
        """최근 파일 스캔 (최적화)"""
        files = []
        max_files = 100  # 최대 100개로 제한
        
        recent_paths = [
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft\\Windows\\Recent'),
        ]
        
        for recent_path in recent_paths:
            if not os.path.exists(recent_path) or len(files) >= max_files:
                continue
            
            try:
                for filename in os.listdir(recent_path):
                    if not self.scanning or len(files) >= max_files:
                        break
                    
                    file_path = os.path.join(recent_path, filename)
                    
                    if not os.path.isfile(file_path):
                        continue
                    
                    try:
                        stat = os.stat(file_path)
                        
                        files.append({
                            'name': filename,
                            'size': self.format_size(stat.st_size),
                            'type': os.path.splitext(filename)[1][1:].upper() or 'LNK',
                            'deleted_time': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            'original_path': file_path,
                            'source': '최근파일',
                            'actual_path': file_path
                        })
                    except:
                        continue
            except PermissionError:
                continue
        
        return files
    
    def filter_files(self, files):
        """파일 필터링"""
        filtered = []
        
        search_term = self.search_var.get().lower()
        file_type = self.file_type_var.get()
        
        type_extensions = {
            "문서": ['.txt', '.doc', '.docx', '.pdf', '.xlsx', '.pptx'],
            "이미지": ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
            "비디오": ['.mp4', '.avi', '.mkv', '.mov', '.wmv'],
            "압축": ['.zip', '.rar', '.7z', '.tar', '.gz']
        }
        
        for file_info in files:
            # 파일명 검색
            if search_term and search_term not in file_info['name'].lower():
                continue
            
            # 파일 형식 필터
            if file_type != "모든 파일":
                ext = os.path.splitext(file_info['name'])[1].lower()
                if file_type in type_extensions:
                    if ext not in type_extensions[file_type]:
                        continue
            
            filtered.append(file_info)
        
        return filtered

    def recover_files(self):
        """선택된 파일 복구"""
        selected = self.tree.selection()
        
        if not selected:
            messagebox.showwarning("경고", "복구할 파일을 선택하세요.")
            return
        
        recovery_path = filedialog.askdirectory(title="복구 위치 선택")
        if not recovery_path:
            return
        
        self.status_label.config(text="파일 복구 중...")
        self.progress_var.set(0)
        
        total = len(selected)
        recovered_count = 0
        failed_files = []
        
        for idx, item in enumerate(selected):
            values = self.tree.item(item)['values']
            file_name = values[0]
            
            progress = (idx + 1) / total * 100
            self.progress_var.set(progress)
            self.status_label.config(text=f"복구 중... {idx + 1}/{total}")
            
            # 실제 파일 복구
            file_info = self.recovered_files[idx] if idx < len(self.recovered_files) else None
            
            if file_info and 'actual_path' in file_info:
                try:
                    source_path = file_info['actual_path']
                    dest_path = os.path.join(recovery_path, file_name)
                    
                    # 파일명 중복 처리
                    counter = 1
                    base_name, ext = os.path.splitext(file_name)
                    while os.path.exists(dest_path):
                        dest_path = os.path.join(recovery_path, f"{base_name}_{counter}{ext}")
                        counter += 1
                    
                    # 파일 복사
                    shutil.copy2(source_path, dest_path)
                    recovered_count += 1
                except Exception as e:
                    failed_files.append(f"{file_name}: {str(e)}")
            
            self.root.update_idletasks()
        
        self.progress_var.set(100)
        self.status_label.config(text=f"복구 완료! {recovered_count}/{total} 파일 성공")
        
        result_msg = f"{recovered_count}개 파일이 성공적으로 복구되었습니다.\n복구 위치: {recovery_path}"
        
        if failed_files:
            result_msg += f"\n\n실패한 파일 ({len(failed_files)}개):\n" + "\n".join(failed_files[:5])
            if len(failed_files) > 5:
                result_msg += f"\n... 외 {len(failed_files) - 5}개"
        
        messagebox.showinfo("복구 완료", result_msg)

    def get_drives(self):
        """사용 가능한 드라이브 목록"""
        drives = []
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        return drives
    
    def format_size(self, size_bytes):
        """파일 크기 포맷"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def select_all(self):
        """전체 선택"""
        for item in self.tree.get_children():
            self.tree.selection_add(item)
    
    def deselect_all(self):
        """선택 해제"""
        self.tree.selection_remove(*self.tree.get_children())
    
    def export_list(self):
        """파일 목록 내보내기"""
        if not self.recovered_files:
            messagebox.showwarning("경고", "내보낼 파일 목록이 없습니다.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON 파일", "*.json"), ("텍스트 파일", "*.txt")]
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.recovered_files, f, ensure_ascii=False, indent=2)
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("복구 가능한 파일 목록\n")
                        f.write("=" * 80 + "\n\n")
                        for file_info in self.recovered_files:
                            f.write(f"파일명: {file_info['name']}\n")
                            f.write(f"크기: {file_info['size']}\n")
                            f.write(f"형식: {file_info['type']}\n")
                            f.write(f"삭제 시간: {file_info['deleted_time']}\n")
                            f.write(f"원본 경로: {file_info['original_path']}\n")
                            f.write(f"복구 소스: {file_info['source']}\n")
                            f.write("-" * 80 + "\n")
                
                messagebox.showinfo("성공", f"파일 목록이 저장되었습니다.\n{file_path}")
            except Exception as e:
                messagebox.showerror("오류", f"파일 저장 중 오류:\n{str(e)}")
    
    def scan_damaged_qr_codes(self):
        """손상된 QR 코드 이미지 스캔"""
        files = []
        
        # 선택된 드라이브의 주요 폴더만 스캔
        selected_drive = self.drive_var.get()
        if selected_drive:
            base_path = selected_drive + "\\"
        else:
            base_path = os.environ.get('USERPROFILE', 'C:\\Users')
        
        # QR 코드가 있을 만한 경로들 (상대 경로)
        search_folders = ['Pictures', 'Downloads', 'Desktop']
        
        qr_extensions = ['.png', '.jpg', '.jpeg', '.bmp']
        max_files = 50  # 최대 50개만 스캔
        
        for folder in search_folders:
            if not self.scanning or len(files) >= max_files:
                break
            
            if selected_drive:
                search_path = os.path.join(base_path, 'Users')
                if not os.path.exists(search_path):
                    continue
                # 첫 번째 사용자 폴더 찾기
                try:
                    users = [d for d in os.listdir(search_path) 
                            if os.path.isdir(os.path.join(search_path, d)) 
                            and d not in ['Public', 'Default', 'All Users']]
                    if users:
                        search_path = os.path.join(search_path, users[0], folder)
                except:
                    continue
            else:
                search_path = os.path.join(base_path, folder)
            
            if not os.path.exists(search_path):
                continue
            
            try:
                # 최대 깊이 2로 제한
                for root, dirs, filenames in os.walk(search_path):
                    # 깊이 제한
                    depth = root[len(search_path):].count(os.sep)
                    if depth > 2:
                        dirs[:] = []
                        continue
                    
                    # 시스템 폴더 제외
                    dirs[:] = [d for d in dirs if not d.startswith('.') 
                              and d.lower() not in ['cache', 'temp', 'appdata']]
                    
                    for filename in filenames:
                        if not self.scanning or len(files) >= max_files:
                            break
                        
                        # QR 코드 이미지 파일만
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in qr_extensions:
                            continue
                        
                        # 파일명에 'qr' 포함만
                        if 'qr' not in filename.lower():
                            continue
                        
                        file_path = os.path.join(root, filename)
                        
                        try:
                            stat = os.stat(file_path)
                            
                            # 파일 크기 제한 (10KB ~ 5MB)
                            if stat.st_size < 10240 or stat.st_size > 5242880:
                                continue
                            
                            files.append({
                                'name': filename,
                                'size': self.format_size(stat.st_size),
                                'type': 'QR-' + ext[1:].upper(),
                                'deleted_time': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                'original_path': file_path,
                                'source': '손상된QR',
                                'actual_path': file_path,
                                'is_damaged_qr': True
                            })
                        except:
                            continue
            except PermissionError:
                continue
        
        return files
    
    def check_qr_code(self, image_path):
        """QR 코드 확인 및 손상 여부 체크"""
        try:
            from pyzbar import pyzbar
            from PIL import Image
            
            # 이미지 열기
            img = Image.open(image_path)
            
            # QR 코드 디코딩 시도
            decoded = pyzbar.decode(img)
            
            # QR 코드가 있지만 디코딩 실패 = 손상됨
            if not decoded:
                # 이미지 크기가 QR 코드 크기와 유사한지 확인
                width, height = img.size
                if 50 < width < 2000 and 50 < height < 2000:
                    # 정사각형에 가까운지 확인
                    ratio = width / height if height > 0 else 0
                    if 0.8 < ratio < 1.2:
                        return True, True  # QR 코드이지만 손상됨
            else:
                return True, False  # QR 코드이고 정상
            
            return False, False  # QR 코드 아님
            
        except ImportError:
            # pyzbar 없으면 파일명으로만 판단
            return True, True
        except Exception as e:
            return False, False
    
    def recover_qr_code(self):
        """손상된 QR 코드 복구 - 파일 선택"""
        # 파일 선택 대화상자
        qr_file = filedialog.askopenfilename(
            title="복구할 QR 코드 이미지 선택",
            filetypes=[
                ("이미지 파일", "*.png *.jpg *.jpeg *.bmp *.gif"),
                ("PNG 이미지", "*.png"),
                ("JPEG 이미지", "*.jpg *.jpeg"),
                ("모든 파일", "*.*")
            ]
        )
        
        if not qr_file:
            return
        
        # 라이브러리 확인
        try:
            import cv2
            import numpy as np
            from PIL import Image, ImageEnhance, ImageFilter
            from pyzbar import pyzbar
        except ImportError:
            result = messagebox.askyesno("라이브러리 필요", 
                               "QR 복구에 필요한 라이브러리가 없습니다.\n\n"
                               "다음 라이브러리가 필요합니다:\n"
                               "- opencv-python\n"
                               "- pillow\n"
                               "- pyzbar\n"
                               "- numpy\n\n"
                               "지금 설치하시겠습니까?")
            
            if result:
                try:
                    import subprocess
                    self.status_label.config(text="라이브러리 설치 중...")
                    self.root.update()
                    
                    subprocess.run([sys.executable, "-m", "pip", "install", 
                                  "opencv-python", "pillow", "pyzbar", "numpy"],
                                 check=True)
                    
                    messagebox.showinfo("설치 완료", 
                                      "라이브러리 설치가 완료되었습니다.\n"
                                      "다시 QR 복구를 시도해주세요.")
                except Exception as e:
                    messagebox.showerror("설치 실패", f"라이브러리 설치 실패:\n{str(e)}")
            return
        
        # QR 복구 진행
        self.status_label.config(text="QR 코드 복구 중...")
        self.progress_var.set(0)
        self.root.update()
        
        # 복구 시도
        recovered_image, decoded_data = self.auto_recover_qr(qr_file)
        
        self.progress_var.set(100)
        
        if decoded_data:
            # 성공 메시지
            result_msg = "✅ QR 코드 복구 성공!\n\n"
            result_msg += f"📄 디코딩된 데이터:\n{decoded_data}\n\n"
            
            # 복구된 이미지 저장 여부 확인
            save_result = messagebox.askyesno("복구 성공", 
                                             result_msg + "복구된 이미지를 저장하시겠습니까?")
            
            if save_result:
                # 저장 위치 선택
                base_name = os.path.basename(qr_file)
                name, ext = os.path.splitext(base_name)
                default_name = f"{name}_recovered{ext}"
                
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    initialfile=default_name,
                    filetypes=[
                        ("PNG 이미지", "*.png"),
                        ("JPEG 이미지", "*.jpg"),
                        ("모든 파일", "*.*")
                    ]
                )
                
                if save_path:
                    cv2.imwrite(save_path, recovered_image)
                    messagebox.showinfo("저장 완료", 
                                      f"복구된 이미지가 저장되었습니다.\n\n{save_path}")
        else:
            # 실패 메시지
            fail_msg = "❌ QR 코드를 복구할 수 없습니다.\n\n"
            fail_msg += "다음을 확인하세요:\n"
            fail_msg += "• QR 코드가 너무 심하게 손상되지 않았는지\n"
            fail_msg += "• 이미지가 흐릿하지 않은지\n"
            fail_msg += "• 조명이 적절한지\n"
            fail_msg += "• QR 코드 전체가 포함되어 있는지\n\n"
            fail_msg += "💡 팁: 더 선명한 이미지로 재촬영하거나\n"
            fail_msg += "다른 각도에서 촬영해보세요."
            
            messagebox.showwarning("복구 실패", fail_msg)
        
        self.status_label.config(text="대기 중...")
        self.progress_var.set(0)
    
    def auto_recover_qr(self, image_path):
        """QR 코드 자동 복구"""
        try:
            import cv2
            import numpy as np
            from PIL import Image, ImageEnhance, ImageFilter
            from pyzbar import pyzbar
            
            # 이미지 로드
            img = cv2.imread(image_path)
            if img is None:
                return None, None
            
            # 복구 기법들 순차 적용
            techniques = [
                self.qr_denoise,
                self.qr_enhance_contrast,
                self.qr_sharpen,
                self.qr_binarize,
                self.qr_fix_perspective
            ]
            
            current = img.copy()
            
            for technique in techniques:
                current = technique(current)
                
                # 각 단계마다 디코딩 시도
                decoded = self.try_decode_qr_cv(current)
                if decoded:
                    return current, decoded
            
            # 여러 각도로 회전 시도
            for angle in [0, 90, 180, 270, -5, 5, -10, 10]:
                rotated = self.qr_rotate(current, angle)
                decoded = self.try_decode_qr_cv(rotated)
                if decoded:
                    return rotated, decoded
            
            return current, None
            
        except Exception as e:
            print(f"QR 복구 오류: {e}")
            return None, None
    
    def qr_denoise(self, img):
        """노이즈 제거"""
        try:
            import cv2
            return cv2.fastNlMeansDenoisingColored(img, None, 10, 10, 7, 21)
        except:
            return img
    
    def qr_enhance_contrast(self, img):
        """대비 향상"""
        try:
            import cv2
            from PIL import Image, ImageEnhance
            pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
            enhancer = ImageEnhance.Contrast(pil_img)
            enhanced = enhancer.enhance(2.0)
            return cv2.cvtColor(np.array(enhanced), cv2.COLOR_RGB2BGR)
        except:
            return img
    
    def qr_sharpen(self, img):
        """선명화"""
        try:
            import cv2
            from PIL import Image, ImageFilter
            pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
            sharpened = pil_img.filter(ImageFilter.SHARPEN)
            return cv2.cvtColor(np.array(sharpened), cv2.COLOR_RGB2BGR)
        except:
            return img
    
    def qr_binarize(self, img):
        """이진화"""
        try:
            import cv2
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            binary = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                          cv2.THRESH_BINARY, 11, 2)
            return cv2.cvtColor(binary, cv2.COLOR_GRAY2BGR)
        except:
            return img
    
    def qr_fix_perspective(self, img):
        """왜곡 보정"""
        try:
            import cv2
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, binary = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
            contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            if contours:
                largest = max(contours, key=cv2.contourArea)
                epsilon = 0.02 * cv2.arcLength(largest, True)
                approx = cv2.approxPolyDP(largest, epsilon, True)
                
                if len(approx) == 4:
                    pts = approx.reshape(4, 2).astype("float32")
                    width = height = 500
                    dst = np.array([[0, 0], [width-1, 0], [width-1, height-1], [0, height-1]], 
                                  dtype="float32")
                    M = cv2.getPerspectiveTransform(pts, dst)
                    return cv2.warpPerspective(img, M, (width, height))
            
            return img
        except:
            return img
    
    def qr_rotate(self, img, angle):
        """회전"""
        try:
            import cv2
            height, width = img.shape[:2]
            center = (width // 2, height // 2)
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            return cv2.warpAffine(img, M, (width, height), 
                                 borderMode=cv2.BORDER_CONSTANT, borderValue=(255, 255, 255))
        except:
            return img
    
    def try_decode_qr_cv(self, img):
        """QR 코드 디코딩 시도"""
        try:
            import cv2
            from PIL import Image
            from pyzbar import pyzbar
            
            rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(rgb)
            decoded = pyzbar.decode(pil_img)
            
            if decoded:
                return decoded[0].data.decode('utf-8')
            return None
        except:
            return None
    
    def get_available_drives(self):
        """사용 가능한 드라이브 목록"""
        drives = []
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:"
            if os.path.exists(drive + "\\"):
                drives.append(drive)
        return drives
    
    def show_help(self):
        """도움말 표시"""
        help_window = tk.Toplevel(self.root)
        help_window.title("도움말")
        help_window.geometry("700x600")
        
        # 스크롤 가능한 텍스트
        text_frame = ttk.Frame(help_window, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        help_text = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set,
                           font=("맑은 고딕", 10))
        help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=help_text.yview)
        
        help_content = """
DataAnchor 도움말
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 기본 사용법

1. 드라이브 선택
   - 스캔할 드라이브를 선택하세요
   - 특정 드라이브만 선택하면 스캔 속도가 빨라집니다

2. 복구 소스 선택
   ✓ 휴지통: 휴지통에서 삭제된 파일
   ✓ 섀도우 복사본: 시스템 복원 지점의 파일
   ✓ 임시 파일: 임시 폴더의 백업 파일
   ✓ 최근 파일: 최근 사용한 파일 추적

3. 파일 형식 선택
   - 모든 파일 / 문서 / 이미지 / 비디오 / 압축

4. 스캔 시작
   - "스캔 시작" 버튼 클릭
   - 진행 상황 확인

5. 파일 복구
   - 복구할 파일 선택 (Ctrl+클릭으로 다중 선택)
   - "선택 파일 복구" 클릭
   - 복구 위치 선택

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔧 주요 기능

• 휴지통 복구
  - 휴지통을 비우기 전 파일 복구
  - 원본 파일명 자동 복원
  - 모든 드라이브 지원

• 섀도우 복사본 (VSS)
  - 시스템 복원 지점에서 파일 복구
  - 관리자 권한 필요
  - 이전 버전 파일 접근

• QR 코드 복구
  - 손상된 QR 이미지 자동 복구
  - 노이즈 제거, 대비 향상, 왜곡 보정
  - 자동 디코딩 및 데이터 추출

• 파티션 복구 (NEW!)
  - 삭제되거나 손상된 파티션 검색
  - 드라이브 문자 할당
  - 파일시스템 검사 및 복구
  - 파티션 테이블 백업

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💾 파티션 복구 사용법

1. "파티션 복구" 버튼 클릭
2. 복구할 디스크 선택
3. "파티션 스캔" 클릭
4. 복구 가능한 파티션 확인 (노란색 강조)
5. 필요한 작업 수행:
   - 드라이브 문자 할당
   - 파일시스템 검사
   - 파티션 테이블 백업

⚠️ 파티션 복구 주의사항:
  - 반드시 관리자 권한으로 실행
  - 중요 데이터는 사전 백업 필수
  - 잘못된 조작 시 데이터 손실 위험

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚡ 성능 최적화 팁

1. 특정 드라이브만 선택
   → 전체 스캔보다 10배 빠름

2. 파일 형식 필터 사용
   → 불필요한 파일 제외

3. 필요한 복구 소스만 선택
   → 스캔 시간 단축

4. 파일명 검색 활용
   → 특정 파일만 빠르게 찾기

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ 주의사항

• 관리자 권한
  - 섀도우 복사본 접근 시 필요
  - 파티션 복구 시 필수
  - 우클릭 → "관리자 권한으로 실행"

• 복구 위치
  - 원본과 다른 드라이브에 복구 권장
  - 같은 드라이브 사용 시 덮어쓰기 위험

• 복구 성공률
  - 파일 삭제 후 빠르게 복구할수록 높음
  - 디스크 사용 최소화 권장

• QR 코드 복구
  - 50% 이상 손상 시 복구 어려움
  - 선명한 이미지일수록 성공률 높음

• 파티션 복구
  - 데이터 손실 위험 높음
  - 전문가 도움 권장
  - 중요 데이터는 반드시 백업

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 문제 해결

Q: 파일이 발견되지 않음
A: 다른 드라이브 선택, 파일 형식을 "모든 파일"로 변경

Q: 스캔이 너무 느림
A: 특정 드라이브만 선택, 파일 형식 필터 사용

Q: 복구된 파일이 열리지 않음
A: 파일이 부분적으로 손상됨, 다른 복구 소스 시도

Q: 섀도우 복사본이 없음
A: 시스템 복원 기능 활성화 필요

Q: 파티션이 보이지 않음
A: 관리자 권한 확인, 디스크 관리에서 확인

Q: 드라이브 문자 할당 실패
A: 사용 가능한 문자 확인, 디스크 오류 검사

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
        
        help_text.insert(1.0, help_content)
        help_text.config(state=tk.DISABLED)
        
        ttk.Button(help_window, text="닫기", command=help_window.destroy).pack(pady=10)
    
    def show_about(self):
        """정보 표시"""
        about_msg = """
DataAnchor v1.0
데이터 복구 도구

━━━━━━━━━━━━━━━━━━━━━━━━━━━━

제작자: Dangel

━━━━━━━━━━━━━━━━━━━━━━━━━━━━

주요 기능:
• 휴지통 파일 복구
• 섀도우 복사본 (VSS) 복구
• 임시 파일 복구
• 최근 파일 추적
• 손상된 QR 코드 복구
• 파티션 복구 및 관리

━━━━━━━━━━━━━━━━━━━━━━━━━━━━

기술 스택:
• Python 3.x
• tkinter (GUI)
• OpenCV (이미지 처리)
• pywin32 (Windows API)
• pyzbar (QR 디코딩)
• PowerShell (파티션 관리)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━

© 2024 Dangel. All rights reserved.
        """
        
        messagebox.showinfo("프로그램 정보", about_msg)
    
    def open_partition_recovery(self):
        """파티션 복구 창 열기"""
        # 파티션 복구 모듈 확인
        if not self.partition_recovery:
            messagebox.showerror("오류", 
                               "파티션 복구 모듈을 로드할 수 없습니다.\n\n"
                               "partition_recovery.py 파일이 있는지 확인하세요.")
            return
        
        try:
            # 파티션 복구 창
            partition_window = tk.Toplevel(self.root)
            partition_window.title("파티션 복구 도구")
            partition_window.geometry("1100x1050")
            
            print("파티션 복구 창 생성...")
            
            # 관리자 권한 경고
            if not self.partition_recovery.is_admin():
                warning_frame = ttk.Frame(partition_window, padding="10")
                warning_frame.pack(fill=tk.X)
                
                ttk.Label(warning_frame, 
                         text="⚠️ 관리자 권한 없음 - 일부 기능 제한", 
                         font=("맑은 고딕", 10, "bold"),
                         foreground="red").pack()
                
                ttk.Button(warning_frame, text="관리자 권한으로 재실행", 
                          command=self.restart_as_admin).pack(pady=5)
            
            # 상단
            top_frame = ttk.Frame(partition_window, padding="10")
            top_frame.pack(fill=tk.X)
            
            ttk.Label(top_frame, text="파티션 복구 도구", 
                     font=("맑은 고딕", 14, "bold")).pack()
            ttk.Label(top_frame, text="삭제되거나 손상된 파티션 스캔 및 복구", 
                     font=("맑은 고딕", 9)).pack()
            
            # 디스크 선택
            disk_frame = ttk.LabelFrame(partition_window, text="디스크 선택", padding="10")
            disk_frame.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Label(disk_frame, text="디스크:").grid(row=0, column=0, padx=5)
            
            disk_var = tk.StringVar()
            disk_combo = ttk.Combobox(disk_frame, textvariable=disk_var, width=50, state="readonly")
            disk_combo.grid(row=0, column=1, padx=5)
            
            # 디스크 목록 로드
            disks = self.partition_recovery.list_physical_disks()
            disk_values = [f"디스크 {d['number']}: {d['name']} ({d['size']})" for d in disks]
            disk_combo['values'] = disk_values
            if disk_values:
                disk_combo.current(0)
            
            ttk.Button(disk_frame, text="새로고침", width=12).grid(row=0, column=2, padx=5)
            
            # 파티션 목록
            list_frame = ttk.LabelFrame(partition_window, text="파티션 목록", padding="10")
            list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            columns = ("디스크", "파티션", "드라이브", "크기", "형식", "상태")
            tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
            
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=100)
            
            scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # 버튼
            btn_frame = ttk.Frame(partition_window, padding="10")
            btn_frame.pack(fill=tk.X)
            
            ttk.Button(btn_frame, text="파티션 스캔", width=15).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="닫기", command=partition_window.destroy, width=15).pack(side=tk.RIGHT, padx=5)
            
            # 상태
            status_label = ttk.Label(btn_frame, text="대기 중...", font=("맑은 고딕", 9))
            status_label.pack(side=tk.LEFT, padx=20)
            
            print("파티션 복구 창 완료")
            
        except Exception as e:
            print(f"오류: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("오류", f"창을 열 수 없습니다.\n\n{str(e)}")
    
    def restart_as_admin(self):
        """관리자 권한으로 재실행"""
        try:
            import sys
            import ctypes
            import os
            
            # 관리자 권한 확인
            if ctypes.windll.shell32.IsUserAnAdmin():
                messagebox.showinfo("알림", "이미 관리자 권한으로 실행 중입니다.")
                return
            
            # 현재 스크립트 경로
            script = os.path.abspath(sys.argv[0])
            
            # 관리자 권한으로 재실행
            result = ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas",  # 관리자 권한 요청
                sys.executable,  # python.exe
                f'"{script}"',  # 현재 스크립트
                None,  # 작업 디렉토리
                1  # SW_SHOWNORMAL
            )
            
            # ShellExecuteW 반환값:
            # > 32: 성공
            # <= 32: 실패
            if result > 32:
                # 성공: 현재 프로그램 종료
                messagebox.showinfo("재실행", 
                                  "관리자 권한으로 프로그램을 재실행합니다.\n\n"
                                  "새 창이 열리면 이 창은 자동으로 닫힙니다.")
                self.root.after(1000, self.root.quit)  # 1초 후 종료
            else:
                # 실패: 오류 메시지
                messagebox.showwarning("취소됨", 
                                     "관리자 권한 요청이 취소되었거나 실패했습니다.\n\n"
                                     "일부 기능이 제한될 수 있습니다.")
                
        except Exception as e:
            messagebox.showerror("오류", 
                               f"관리자 권한으로 실행할 수 없습니다.\n\n"
                               f"오류: {str(e)}\n\n"
                               "수동으로 관리자 권한으로 실행해주세요:\n"
                               "1. 프로그램 우클릭\n"
                               "2. '관리자 권한으로 실행' 선택")

def main():
    root = tk.Tk()
    app = DataAnchor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
