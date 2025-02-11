import os
import re
import chardet
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
import logging
from datetime import datetime

# 修改日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # 只保留控制台输出
    ]
)

@dataclass
class LyricLine:
    """歌词行数据结构"""
    start_time: float  # 开始时间（秒）
    end_time: float   # 结束时间（秒）
    text: str         # 歌词文本
    is_current: bool = False  # 是否是当前行

class Config:
    """KTV样式配置"""
    # 字体设置
    FONT_NAME = "微软雅黑"
    FONT_SIZE = 80  # 歌词字体大小
    TITLE_FONT_SIZE = 60  # 标题字体大小
    BOLD = 1        # 加粗
    OUTLINE = 4     # 描边宽度
    
    # 颜色设置（ASS格式：BGR）
    CURRENT_COLOR = "&H00D4A8AF"     # 当前行颜色
    OTHER_COLOR = "&H00FFFFFF"       # 其他行颜色
    TITLE_COLOR = "&H00FFF0E0"      # 标题颜色（浅金色）
    OUTLINE_COLOR = "&H00000000"     # 描边颜色
    
    # 位置设置（基于1080p）
    TITLE_Y = 50               # 标题Y坐标
    BOTTOM_Y1 = 900           # 歌词上面一行的Y坐标
    BOTTOM_Y2 = 980           # 歌词下面一行的Y坐标
    CENTER_X = 960            # 屏幕中心X坐标
    MARGIN = 25               # 与中轴线的间距
    RESOLUTION = "1920x1080"  # 视频分辨率
    FADE_DURATION = 0.1       # 渐入渐出时间（秒）
    
    # 计算左右位置
    @classmethod
    def get_left_x(cls) -> int:
        return cls.CENTER_X - cls.MARGIN  # 中轴线左侧
        
    @classmethod
    def get_right_x(cls) -> int:
        return cls.CENTER_X + cls.MARGIN  # 中轴线右侧

class LyricsConverter:
    """歌词转换器主类"""
    # 预编译正则表达式
    LRC_TIME_PATTERN = re.compile(r'\[(\d{2}):(\d{2})\.(\d{2,3})\]')
    SRT_PATTERN = re.compile(r'(\d+)\n(\d{2}:\d{2}:\d{2},\d{3}) --> (\d{2}:\d{2}:\d{2},\d{3})\n((?:.*\n)*?)\n')
    
    def __init__(self):
        # 修改输入输出路径
        self.input_dir = Path("input")  # 输入根目录
        self.output_dir = Path("middle/ass")  # 输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_encodings = ['utf-8', 'gbk', 'big5', 'shift-jis']
        
    def detect_encoding(self, file_path: Path) -> tuple[str, bytes]:
        """检测文件编码，返回编码和文件内容"""
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                
            # 首先尝试 chardet 检测
            result = chardet.detect(raw_data)
            detected_encoding = result.get('encoding', 'utf-8')
            confidence = result.get('confidence', 0)
            
            if confidence >= 0.8:
                return detected_encoding, raw_data
                
            # 置信度低时，尝试备选编码列表
            for encoding in self.fallback_encodings:
                try:
                    raw_data.decode(encoding)
                    logging.info(f"使用备选编码 {encoding} 成功解码文件: {file_path}")
                    return encoding, raw_data
                except UnicodeDecodeError:
                    continue
                    
            # 如果所有备选编码都失败，返回 chardet 检测结果
            logging.warning(f"所有备选编码均解码失败，使用 chardet 检测结果: {detected_encoding}")
            return detected_encoding, raw_data
            
        except IOError as e:
            logging.error(f"读取文件失败: {file_path}, 错误: {str(e)}")
            raise
            
    def read_file(self, file_path: Path) -> str:
        """读取文件内容并转换为UTF-8"""
        try:
            encoding, raw_data = self.detect_encoding(file_path)
            try:
                return raw_data.decode(encoding)
            except UnicodeDecodeError as e:
                logging.error(f"文件解码失败: {file_path}, 编码: {encoding}, 错误: {str(e)}")
                raise
        except Exception as e:
            logging.error(f"文件处理失败: {file_path}, 错误: {str(e)}")
            raise
            
    def escape_special_chars(self, text: str) -> str:
        """处理特殊字符"""
        replacements = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&apos;'
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text
        
    def parse_lrc(self, content: str) -> List[LyricLine]:
        """解析LRC格式歌词"""
        lyrics = []
        
        try:
            for line in content.splitlines():
                if not line.strip() or not line.startswith('['):
                    continue
                    
                # 提取所有时间标签
                matches = list(self.LRC_TIME_PATTERN.finditer(line))
                if not matches:
                    continue
                    
                times = []
                for match in matches:
                    try:
                        minutes = int(match.group(1))
                        seconds = int(match.group(2))
                        ms = int(match.group(3))
                        # 验证时间值的合法性
                        if minutes > 59 or seconds > 59 or ms > 999:
                            logging.warning(f"跳过无效时间标签: [{minutes}:{seconds}.{ms}]")
                            continue
                        # 统一转换为秒
                        total_seconds = minutes * 60 + seconds + ms / (1000 if len(match.group(3)) == 3 else 100)
                        times.append(total_seconds)
                    except ValueError as e:
                        logging.warning(f"时间标签解析失败: {match.group()}, 错误: {str(e)}")
                        continue
                        
                if not times:
                    continue
                    
                # 提取歌词文本
                text = self.LRC_TIME_PATTERN.sub('', line).strip()
                if not text:  # 跳过空歌词
                    continue
                    
                text = self.escape_special_chars(text)
                
                # 处理多时间标签，确保时间间隔合理
                for i, start_time in enumerate(times):
                    end_time = times[i + 1] if i + 1 < len(times) else start_time + 5
                    if end_time <= start_time:
                        end_time = start_time + 5  # 确保结束时间大于开始时间
                    lyrics.append(LyricLine(start_time, end_time, text))
                    
            if not lyrics:
                raise ValueError("未找到有效歌词")
                
            return sorted(lyrics, key=lambda x: x.start_time)
            
        except Exception as e:
            logging.error(f"LRC解析失败: {str(e)}")
            raise

    def generate_ass_header(self) -> str:
        """生成ASS文件头部"""
        width, height = Config.RESOLUTION.split('x')
        return f"""[Script Info]
Title: KTV Style Lyrics
ScriptType: v4.00+
WrapStyle: 0
ScaledBorderAndShadow: yes
YCbCr Matrix: TV.601
PlayResX: {width}
PlayResY: {height}

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Current,{Config.FONT_NAME},{Config.FONT_SIZE},{Config.CURRENT_COLOR},&H000000FF,{Config.OUTLINE_COLOR},&H00000000,{Config.BOLD},0,1,{Config.OUTLINE},0,2,0,0,0,1
Style: Other,{Config.FONT_NAME},{Config.FONT_SIZE},{Config.OTHER_COLOR},&H000000FF,{Config.OUTLINE_COLOR},&H00000000,{Config.BOLD},0,1,{Config.OUTLINE},0,2,0,0,0,1
Style: Title,{Config.FONT_NAME},{Config.TITLE_FONT_SIZE},{Config.TITLE_COLOR},&H000000FF,{Config.OUTLINE_COLOR},&H00000000,{Config.BOLD},0,1,{Config.OUTLINE},0,8,0,0,0,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""

    def format_time(self, seconds: float) -> str:
        """将秒转换为ASS时间格式 (H:MM:SS.cc)"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        centisecs = int((seconds * 100) % 100)
        return f"{hours}:{minutes:02d}:{secs:02d}.{centisecs:02d}"

    def parse_srt_time(self, time_str: str) -> float:
        """解析SRT时间格式 (HH:MM:SS,mmm)"""
        try:
            hours, minutes, seconds = time_str.replace(',', '.').split(':')
            hours = int(hours)
            minutes = int(minutes)
            seconds = float(seconds)
            
            # 验证时间值的合法性
            if hours > 23 or minutes > 59 or seconds >= 60:
                raise ValueError(f"无效的时间值: {time_str}")
                
            return float(hours) * 3600 + float(minutes) * 60 + seconds
        except Exception as e:
            raise ValueError(f"时间格式解析失败: {time_str}, 错误: {str(e)}")

    def parse_srt(self, content: str) -> List[LyricLine]:
        """解析SRT格式字幕"""
        lyrics = []
        
        matches = self.SRT_PATTERN.finditer(content)
        for match in matches:
            try:
                start_time = self.parse_srt_time(match.group(2))
                end_time = self.parse_srt_time(match.group(3))
                text = match.group(4).strip().replace('\n', ' ')
                text = self.escape_special_chars(text)
                lyrics.append(LyricLine(start_time, end_time, text))
            except ValueError as e:
                logging.warning(f"跳过无效字幕行: {match.group()}, 错误: {str(e)}")
                continue
        
        return sorted(lyrics, key=lambda x: x.start_time)

    def generate_ktv_effects(self, text: str, is_current: bool = True, offset: int = 0) -> str:
        """生成KTV特效文本"""
        if not text.strip():
            return text
        
        # 根据偏移量计算动画效果
        if offset == -2:  # 最上面一行
            return f"{{\\fad(0,{int(Config.FADE_DURATION*1000)})}}{text}"
        elif offset == 2:  # 最下面一行
            return f"{{\\fad({int(Config.FADE_DURATION*1000)},0)}}{text}"
        else:
            return text

    def parse_title_from_filename(self, filename: str) -> tuple[str, str]:
        """从文件名解析歌曲名和作者"""
        # 移除扩展名
        name = os.path.splitext(filename)[0]
        # 尝试分割作者和歌名
        parts = name.split(' - ', 1)
        if len(parts) == 2:
            artist, title = parts
        else:
            artist = "未知歌手"
            title = name
        return artist, title

    def generate_events(self, lyrics: List[LyricLine]) -> List[str]:
        """生成ASS Events部分"""
        events = []
        
        # 添加标题显示
        artist, title = self.parse_title_from_filename(Path(self.current_file).name)
        title_text = f"{artist} - {title}"
        # 标题从开始显示到结束
        events.append(
            f"Dialogue: 0,0:00:00.00,99:00:00.00,Title,,0,0,0,,"
            f"{{\\pos({Config.CENTER_X},{Config.TITLE_Y})\\an8}}{title_text}"
        )
        
        # 生成歌词事件
        for i in range(len(lyrics)):
            current_line = lyrics[i]
            current_start = self.format_time(current_line.start_time)
            
            # 判断当前行显示位置（奇数行在左，偶数行在右）
            is_left_side = (i % 2 == 0)
            
            # 生成当前行（天蓝色）
            pos_x = Config.get_left_x() if is_left_side else Config.get_right_x()
            align = "\\an6" if is_left_side else "\\an4"  # 左侧右对齐，右侧左对齐
            y_pos = Config.BOTTOM_Y1 if is_left_side else Config.BOTTOM_Y2  # 左侧在上，右侧在下
            
            # 如果有下一行，检查时间间隔
            if i < len(lyrics) - 1:
                next_line = lyrics[i + 1]
                time_gap = next_line.start_time - current_line.start_time
                
                if time_gap > 15:  # 如果间隔超过15秒
                    # 当前行显示到结束后再加3秒
                    current_end = self.format_time(current_line.end_time + 6)
                    # 下一行提前3秒出现（白色），到其开始时间结束
                    next_preview_start = self.format_time(next_line.start_time - 3)
                    next_actual_start = self.format_time(next_line.start_time)
                    
                    # 生成当前行
                    event = (
                        f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                        f"{{\\pos({pos_x},{y_pos}){align}}}{current_line.text}"
                    )
                    events.append(event)
                    
                    # 生成下一行预览（白色）
                    next_pos_x = Config.get_right_x() if is_left_side else Config.get_left_x()
                    next_align = "\\an4" if is_left_side else "\\an6"
                    next_y_pos = Config.BOTTOM_Y2 if is_left_side else Config.BOTTOM_Y1
                    
                    # 白色预览显示到实际开始时间
                    event = (
                        f"Dialogue: 0,{next_preview_start},{next_actual_start},Other,,0,0,0,,"
                        f"{{\\pos({next_pos_x},{next_y_pos}){next_align}}}{next_line.text}"
                    )
                    events.append(event)
                    
                    if i < len(lyrics) - 2:  # 如果不是最后一句
                        next_next_line = lyrics[i + 2]
                        # 变成蓝色后显示到下一句开始
                        event = (
                            f"Dialogue: 0,{next_actual_start},{self.format_time(next_next_line.start_time)},Current,,0,0,0,,"
                            f"{{\\pos({next_pos_x},{next_y_pos}){next_align}}}{next_line.text}"
                        )
                    else:
                        # 最后一句显示到其结束时间
                        event = (
                            f"Dialogue: 0,{next_actual_start},{self.format_time(next_line.end_time)},Current,,0,0,0,,"
                            f"{{\\pos({next_pos_x},{next_y_pos}){next_align}}}{next_line.text}"
                        )
                    events.append(event)
                else:
                    # 正常情况，当前行显示到下一行开始
                    current_end = self.format_time(next_line.start_time)
                    
                    # 生成当前行
                    event = (
                        f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                        f"{{\\pos({pos_x},{y_pos}){align}}}{current_line.text}"
                    )
                    events.append(event)
                    
                    # 生成下一行预览（白色）
                    next_pos_x = Config.get_right_x() if is_left_side else Config.get_left_x()
                    next_align = "\\an4" if is_left_side else "\\an6"
                    next_y_pos = Config.BOTTOM_Y2 if is_left_side else Config.BOTTOM_Y1
                    
                    event = (
                        f"Dialogue: 0,{current_start},{current_end},Other,,0,0,0,,"
                        f"{{\\pos({next_pos_x},{next_y_pos}){next_align}}}{next_line.text}"
                    )
                    events.append(event)
            else:
                # 最后一行显示到其结束时间
                current_end = self.format_time(current_line.end_time)
                event = (
                    f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                    f"{{\\pos({pos_x},{y_pos}){align}}}{current_line.text}"
                )
                events.append(event)
        
        return events

    def get_text_width(self, text: str) -> int:
        """估算文本宽度（简化版）"""
        # 假设每个字符宽度为FONT_SIZE/2
        return int(len(text) * Config.FONT_SIZE / 2)

    def convert_file(self, input_path: Path):
        """转换单个文件"""
        self.current_file = input_path  # 保存当前处理的文件名，供标题解析使用
        start_time = datetime.now()
        
        try:
            # 生成输出文件路径
            output_path = self.output_dir / f"{input_path.stem}.ass"
            
            # 检查输出文件是否已存在
            if output_path.exists():
                logging.info(f"文件已存在，跳过转换: {output_path}")
                return
            
            logging.info(f"开始处理文件: {input_path}")
            
            # 检查文件大小
            file_size = input_path.stat().st_size
            if file_size == 0:
                raise ValueError("文件为空")
            if file_size > 10 * 1024 * 1024:  # 10MB
                raise ValueError("文件太大")
                
            content = self.read_file(input_path)
            
            # 根据文件类型选择解析方法
            suffix = input_path.suffix.lower()
            if suffix == '.lrc':
                lyrics = self.parse_lrc(content)
            elif suffix == '.srt':
                lyrics = self.parse_srt(content)
            else:
                raise ValueError(f"不支持的文件类型: {suffix}")
                
            # 检查歌词数量
            if len(lyrics) > 1000:
                logging.warning(f"歌词行数过多: {len(lyrics)}行")
                
            # 生成ASS文件
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_ass_header())
                events = self.generate_events(lyrics)
                f.write('\n'.join(events))
                
            process_time = (datetime.now() - start_time).total_seconds()
            logging.info(f"文件处理完成: {output_path}, 耗时: {process_time:.2f}秒")
            
        except Exception as e:
            logging.error(f"处理文件失败: {input_path}, 错误: {str(e)}")
            raise

    def process_all(self):
        """处理所有文件"""
        if not self.input_dir.exists():
            raise FileNotFoundError(f"输入目录不存在: {self.input_dir}")
            
        total_files = 0
        skipped_files = 0
        converted_files = 0
        failed_files = 0
        
        # 递归搜索所有子目录中的LRC和SRT文件
        for pattern in ['**/*.[lL][rR][cC]', '**/*.[sS][rR][tT]']:
            for file_path in self.input_dir.glob(pattern):
                total_files += 1
                try:
                    # 检查对应的ASS文件是否存在
                    ass_path = self.output_dir / f"{file_path.stem}.ass"
                    if ass_path.exists():
                        logging.info(f"跳过已存在的文件: {ass_path}")
                        skipped_files += 1
                        continue
                        
                    self.convert_file(file_path)
                    converted_files += 1
                    
                except Exception as e:
                    logging.error(f"处理文件失败: {file_path}, 错误: {str(e)}")
                    failed_files += 1
                    continue
        
        # 输出处理统计
        logging.info(f"\n处理完成:")
        logging.info(f"总文件数: {total_files}")
        logging.info(f"已跳过: {skipped_files}")
        logging.info(f"已转换: {converted_files}")
        logging.info(f"失败: {failed_files}")

if __name__ == "__main__":
    converter = LyricsConverter()
    converter.process_all() 