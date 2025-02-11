import os
import shutil
from pathlib import Path
import re

def clean_filename(filename: str) -> str:
    """清理文件名，只保留ffmpeg支持的字符"""
    # 保留文件扩展名
    name, ext = os.path.splitext(filename)
    
    # 替换规则
    # 1. 移除所有撇号和引号
    name = name.replace("'", "").replace('"', "")
    # 2. 保留字母、数字、中文字符、连字符和空格
    name = re.sub(r'[^\w\u4e00-\u9fff\- ]', '', name)
    # 3. 将多个空格替换为单个空格
    name = re.sub(r'\s+', ' ', name)
    # 4. 去除首尾空格
    name = name.strip()
    
    return name + ext

def move_music_files():
    """移动QQ音乐文件到对应目录"""
    # 定义源目录和目标目录
    source_dir = Path(r"C:\Users\Administrator\Music\QQMusic")
    input_lyrics_dir = Path("input/lyrics")
    input_music_dir = Path("input/music")
    middle_dir = Path("middle/Music")
    
    # 确保目标目录存在
    input_lyrics_dir.mkdir(parents=True, exist_ok=True)
    input_music_dir.mkdir(parents=True, exist_ok=True)
    middle_dir.mkdir(parents=True, exist_ok=True)
    
    # 定义文件类型映射
    lyrics_extensions = {'.lrc', '.srt'}
    encrypted_music_extensions = {'.mgg', '.mflac'}
    middle_extensions = {'.ogg', '.flac', '.mp3', '.mgg'}
    
    # 统计移动的文件数
    moved_files = {
        'lyrics': 0,
        'encrypted': 0,
        'middle': 0,
        'overwritten': 0,
        'renamed': 0
    }
    
    # 检查源目录是否存在
    if not source_dir.exists():
        print(f"! QQ音乐目录不存在: {source_dir}")
        return
    
    # 检查是否有需要移动的文件
    need_move = False
    for file_path in source_dir.rglob('*'):
        if file_path.is_file():
            ext = file_path.suffix.lower()
            if ext in lyrics_extensions | encrypted_music_extensions | middle_extensions:
                need_move = True
                break
    
    if not need_move:
        print("→ 没有新的文件需要移动")
        return
    
    # 遍历源目录
    print(f"开始扫描目录: {source_dir}")
    for file_path in source_dir.rglob('*'):
        if not file_path.is_file():
            continue
            
        ext = file_path.suffix.lower()
        file_name = file_path.name
        clean_name = clean_filename(file_name)
        
        # 如果文件名被清理了，记录一下
        if clean_name != file_name:
            print(f"→ 清理文件名: {file_name} -> {clean_name}")
            moved_files['renamed'] += 1
        
        try:
            if ext in lyrics_extensions:
                dest_path = input_lyrics_dir / clean_name
                if dest_path.exists():
                    print(f"→ 覆盖: {clean_name}")
                    moved_files['overwritten'] += 1
                else:
                    print(f"→ 移动到lyrics: {clean_name}")
                shutil.move(str(file_path), str(dest_path))
                moved_files['lyrics'] += 1
                    
            elif ext in encrypted_music_extensions:
                dest_path = input_music_dir / clean_name
                if dest_path.exists():
                    print(f"→ 覆盖: {clean_name}")
                    moved_files['overwritten'] += 1
                else:
                    print(f"→ 移动到music: {clean_name}")
                shutil.move(str(file_path), str(dest_path))
                moved_files['encrypted'] += 1
                    
            elif ext in middle_extensions:
                dest_path = middle_dir / clean_name
                if dest_path.exists():
                    print(f"→ 覆盖: {clean_name}")
                    moved_files['overwritten'] += 1
                else:
                    print(f"→ 移动到middle: {clean_name}")
                shutil.move(str(file_path), str(dest_path))
                moved_files['middle'] += 1
                    
        except Exception as e:
            print(f"! 移动失败 {clean_name}: {str(e)}")
    
    # 打印统计信息
    if any(v > 0 for v in moved_files.values()):
        print("\n处理结果:")
        if moved_files['lyrics'] > 0:
            print(f"移动到lyrics目录: {moved_files['lyrics']} 个文件")
        if moved_files['encrypted'] > 0:
            print(f"移动到music目录: {moved_files['encrypted']} 个文件")
        if moved_files['middle'] > 0:
            print(f"移动到middle目录: {moved_files['middle']} 个文件")
        if moved_files['overwritten'] > 0:
            print(f"覆盖文件: {moved_files['overwritten']} 个")
        if moved_files['renamed'] > 0:
            print(f"清理文件名: {moved_files['renamed']} 个")

if __name__ == "__main__":
    move_music_files() 