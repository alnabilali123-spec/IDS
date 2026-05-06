import scapy.all as scapy
import joblib
import torch
import os
import numpy as np
import warnings
import subprocess
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from plyer import notification
from pathlib import Path

# 1. إعدادات البيئة وتجاهل التحذيرات
warnings.filterwarnings("ignore")

# --- 2. تحميل النماذج الذكية (الترسانة الأمنية) ---
print("⌛ جاري تشغيل المحرك الذكي وتجهيز الدفاعات...")

# المسار كما هو موجود في جهازك تماماً
deep_model_path = "./deep_model_ready"

try:
    # تحميل نماذج Machine Learning
    iso_forest = joblib.load('layer1_sentry_model.pkl')
    xgb_model = joblib.load('cybersecurity_model_v1.pkl')

    # تحميل نموذج Deep Learning (DistilBERT)
    # تم استخدام use_fast=False لحل مشكلة TokenizersBackend في بعض بيئات ويندوز
    tokenizer = AutoTokenizer.from_pretrained(deep_model_path, local_files_only=True, use_fast=False)
    deep_model = AutoModelForSequenceClassification.from_pretrained(deep_model_path, local_files_only=True)
    
    print("✅ تم تحميل جميع الطبقات الدفاعية بنجاح!")
except Exception as e:
    print(f"❌ فشل في تحميل الموديلات: {e}")
    print("💡 نصيحة: تأكد من تشغيل الأمر 'pip install --upgrade transformers' إذا استمرت المشكلة.")
    exit()

# --- 3. وظائف الاستجابة والحظر ---
def send_alert(ip, mac):
    """إرسال إشعار لسطح المكتب عند رصد هجوم"""
    try:
        notification.notify(
            title="🚨 X-Sentry AI: تم رصد هجوم!",
            message=f"IP: {ip}\nMAC: {mac}\nتم الحظر وتأمين الشبكة.",
            app_name="X-Sentry AI",
            timeout=10
        )
    except:
        pass

def block_attacker(ip):
    """إضافة قاعدة حظر في الجدار الناري لويندوز"""
    print(f"🚫 جاري عزل المهاجم: {ip}")
    cmd = f'netsh advfirewall firewall add rule name="X-Sentry_Block_{ip}" dir=in action=block remoteip={ip}'
    subprocess.run(cmd, shell=True, capture_output=True)

# --- 4. محرك تحليل حركة المرور ---
def get_features(packet):
    """استخراج الميزات العشر المطلوبة للموديلات"""
    try:
        if packet.haslayer(scapy.IP):
            protocol = packet.proto
            duration, fwd_pkts, bwd_pkts = 0, 1, 0
            fwd_max = fwd_min = len(packet)
            
            syn_flag = ack_flag = 0
            if packet.haslayer(scapy.TCP):
                flags = str(packet['TCP'].flags)
                syn_flag = 1 if 'S' in flags else 0
                ack_flag = 1 if 'A' in flags else 0
            
            avg_size, pkt_rate = len(packet), 1 
            
            return np.array([[protocol, duration, fwd_pkts, bwd_pkts, fwd_max, fwd_min, syn_flag, ack_flag, avg_size, pkt_rate]])
    except:
        return None

def packet_analyzer(packet):
    """الدالة الرئيسية لإظهار كيفية اتخاذ القرار لكل حزمة"""
    features = get_features(packet)
    if features is not None:
        src_ip = packet[scapy.IP].src
        print(f"\n🔍 فحص حزمة من: {src_ip}")

        # الطبقة 1: كشف الشذوذ (Isolation Forest)
        l1_pred = iso_forest.predict(features)[0]
        if l1_pred == 1:
            print(f"   🟢 الطبقة 1: سلوك طبيعي.")
        else:
            print(f"   ⚠️ الطبقة 1: تم رصد شذوذ (Anomaly)!")

            # الطبقة 2: تصنيف الهجوم (XGBoost)
            l2_pred = xgb_model.predict(features)[0]
            if l2_pred == 0:
                print(f"   🟢 الطبقة 2: الشذوذ غير ضار (False Alarm).")
            else:
                print(f"   🟠 الطبقة 2: نمط هجوم محتمل رُصد بواسطة XGBoost.")

                # الطبقة 3: التأكيد العميق (DistilBERT)
                pkt_summary = str(packet.summary())
                inputs = tokenizer(pkt_summary, return_tensors="pt", truncation=True, padding=True)
                with torch.no_grad():
                    output = deep_model(**inputs)
                    l3_decision = torch.argmax(output.logits).item()
                    
                    if l3_decision == 0:
                        print(f"   🟢 الطبقة 3: BERT يؤكد أن الحزمة آمنة.")
                    else:
                        # القرار النهائي
                        src_mac = packet[scapy.Ether].src if packet.haslayer(scapy.Ether) else "Unknown"
                        print(f"   🔴 الطبقة 3: BERT يؤكد الهجوم! اتخاذ قرار الحظر فوراً.")
                        print(f"   🚫 [FINAL DECISION]: حظر IP: {src_ip}")
                        block_attacker(src_ip)
                        send_alert(src_ip, src_mac)

# --- 5. التشغيل الرسمي على منفذ الـ Hotspot ---
# المنفذ الصحيح لجهاز alhos
target_interface = "‏‏الاتصال المحلي* 2"

print(f"🛡️ نظام X-Sentry AI يراقب الآن المنفذ: {target_interface}")
try:
    scapy.sniff(iface=target_interface, prn=packet_analyzer, store=0)
except Exception as e:
    print(f"❌ خطأ أثناء المراقبة: {e}")