import json
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def read_json_data(filename: str) -> pd.DataFrame:
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
        return pd.DataFrame(json_data["events"])
    except FileNotFoundError:
        print(f"Ошибка: Файл '{filename}' не найден")
        return pd.DataFrame()
    except KeyError:
        print("Ошибка: В JSON файле отсутствует ключ 'events'")
        return pd.DataFrame()


def calculate_event_statistics(dataframe: pd.DataFrame) -> pd.Series:
    if 'signature' not in dataframe.columns:
        print("Ошибка: В данных отсутствует колонка 'signature'")
        return pd.Series()
    
    frequency_data = dataframe['signature'].value_counts()
    
    print("СТАТИСТИКА СОБЫТИЙ ПО СИГНАТУРАМ")
    print("=" * 50)
    print(frequency_data.to_string())
    
    total_events = len(dataframe)
    unique_signatures = dataframe['signature'].nunique()
    
    print(f"\nОбщая информация:")
    print(f"Всего событий: {total_events}")
    print(f"Уникальных сигнатур: {unique_signatures}")
    
    print(f"\nПроцентное распределение:")
    percentages = (frequency_data / total_events * 100).round(1)
    for signature, count in frequency_data.items():
        percentage = percentages[signature]
        print(f"- {signature}: {count} событий ({percentage}%)")
    
    return frequency_data


def create_event_distribution_chart(frequency_series: pd.Series) -> None:
    if frequency_series.empty:
        print("Нет данных для создания графика")
        return
    
    plt.style.use('seaborn-v0_8-darkgrid')
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    colors = sns.color_palette("husl", len(frequency_series))
    
    bars = ax.barh(frequency_series.index, frequency_series.values, color=colors)
    
    for i, (bar, value) in enumerate(zip(bars, frequency_series.values)):
        ax.text(value + 0.5, bar.get_y() + bar.get_height()/2,
                f'{value}', va='center', fontweight='bold')
    
    ax.set_xlabel('Количество событий', fontsize=12, fontweight='bold')
    ax.set_ylabel('Тип события (сигнатура)', fontsize=12, fontweight='bold')
    ax.set_title('РАСПРЕДЕЛЕНИЕ СОБЫТИЙ ИБ ПО СИГНАТУРАМ', 
                fontsize=14, fontweight='bold', pad=20)
    
    ax.tick_params(axis='y', labelsize=10)
    
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    
    output_filename = Path(__file__).parent / 'security_events_distribution.png'
    plt.savefig(output_filename, dpi=150, bbox_inches='tight')
    print(f"\nГрафик сохранен как: {output_filename}")
    
    plt.show()


def generate_statistics_report(frequency_series: pd.Series, output_file: str) -> None:
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write("ОТЧЕТ ПО АНАЛИЗУ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ\n")
            file.write("=" * 60 + "\n\n")
            
            file.write("РАСПРЕДЕЛЕНИЕ СОБЫТИЙ ПО СИГНАТУРАМ:\n")
            file.write("-" * 40 + "\n")
            
            for signature, count in frequency_series.items():
                file.write(f"• {signature}\n")
                file.write(f"  Количество: {count}\n")
            
            total = frequency_series.sum()
            unique = len(frequency_series)
            
            file.write(f"\nОБЩАЯ СТАТИСТИКА:\n")
            file.write(f"Всего событий: {total}\n")
            file.write(f"Уникальных сигнатур: {unique}\n")
            file.write(f"Среднее событий на сигнатуру: {total/unique:.1f}\n")
        
        print(f"Отчет сохранен в файл: {output_file}")
    except Exception as e:
        print(f"Ошибка при сохранении отчета: {e}")


def analyze_time_distribution(dataframe: pd.DataFrame) -> None:
    if 'timestamp' not in dataframe.columns:
        return
    
    dataframe['timestamp'] = pd.to_datetime(dataframe['timestamp'])
    
    dataframe['hour'] = dataframe['timestamp'].dt.hour
    
    hourly_counts = dataframe['hour'].value_counts().sort_index()
    
    print("\nРАСПРЕДЕЛЕНИЕ СОБЫТИЙ ПО ЧАСАМ СУТОК:")
    print("=" * 40)
    print(hourly_counts.to_string())


def main():
    data_file = Path(__file__).parent / "events.json"
    
    print("ЗАГРУЗКА ДАННЫХ...")
    events_df = read_json_data(data_file)
    
    if events_df.empty:
        print("Не удалось загрузить данные. Программа завершена.")
        return
    
    print(f"✓ Загружено {len(events_df)} событий\n")
    
    signature_stats = calculate_event_statistics(events_df)
    
    if not signature_stats.empty:
        create_event_distribution_chart(signature_stats)
        
        report_file = Path(__file__).parent / "security_events_report.txt"
        generate_statistics_report(signature_stats, report_file)
        
        # Дополнительный анализ по времени
        analyze_time_distribution(events_df)
    else:
        print("Не удалось проанализировать данные.")


if __name__ == "__main__":
    main()