import os
import shutil
from pathlib import Path

def move_music_files():
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
    encrypted_music_extensions = {'.mflac', '.mgg'}
    middle_extensions = {'.ogg', '.flac', '.mp3'}
    
    # 计数器
    moved_files = {
        'lyrics': 0,
        'encrypted': 0,
        'middle': 0,
        'overwritten': 0
    }
    
    # 遍历源目录
    print(f"开始扫描目录: {source_dir}")
    for file_path in source_dir.rglob('*'):
        if not file_path.is_file():
            continue
            
        ext = file_path.suffix.lower()
        file_name = file_path.name
        
        try:
            if ext in lyrics_extensions:
                dest_path = input_lyrics_dir / file_name
                if dest_path.exists():
                    print(f"覆盖已存在文件: {file_name}")
                    moved_files['overwritten'] += 1
                else:
                    print(f"移动到lyrics: {file_name}")
                shutil.move(str(file_path), str(dest_path))
                moved_files['lyrics'] += 1
                    
            elif ext in encrypted_music_extensions:
                dest_path = input_music_dir / file_name
                if dest_path.exists():
                    print(f"覆盖已存在文件: {file_name}")
                    moved_files['overwritten'] += 1
                else:
                    print(f"移动到music: {file_name}")
                shutil.move(str(file_path), str(dest_path))
                moved_files['encrypted'] += 1
                    
            elif ext in middle_extensions:
                dest_path = middle_dir / file_name
                if dest_path.exists():
                    print(f"覆盖已存在文件: {file_name}")
                    moved_files['overwritten'] += 1
                else:
                    print(f"移动到middle: {file_name}")
                shutil.move(str(file_path), str(dest_path))
                moved_files['middle'] += 1
                    
        except Exception as e:
            print(f"移动文件 {file_name} 时出错: {str(e)}")
    
    # 打印统计信息
    print("\n处理完成！")
    print(f"移动到lyrics目录: {moved_files['lyrics']} 个文件")
    print(f"移动到music目录: {moved_files['encrypted']} 个文件")
    print(f"移动到middle目录: {moved_files['middle']} 个文件")
    print(f"其中覆盖了: {moved_files['overwritten']} 个文件")

if __name__ == "__main__":
    move_music_files() 