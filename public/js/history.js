(function() {
    'use strict';

    var API = (typeof API_BASE !== 'undefined') ? API_BASE : 'http://127.0.0.1:5000';
    var historyContent = document.getElementById('history-content');

    function getLabel(label) {
        if (typeof translate !== 'undefined') {
            if (label === 'safe') return translate('label.safe');
            if (label === 'suspicious') return translate('label.suspicious');
            if (label === 'malicious') return translate('label.malicious');
            return translate('label.error');
        }
        if (label === 'safe') return 'سليم';
        if (label === 'suspicious') return 'مشبوه';
        if (label === 'malicious') return 'خبيث';
        return label || 'خطأ';
    }

    function getLabelClass(label) {
        if (label === 'safe') return 'safe';
        if (label === 'suspicious') return 'suspicious';
        if (label === 'malicious') return 'malicious';
        return 'error';
    }

    function loadHistory() {
        if (!historyContent) return;

        fetch(API + '/api/saved-results')
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                if (!data || !data.saved_results) {
                    displayEmpty();
                    return;
                }

                var results = data.saved_results || [];
                if (results.length === 0) {
                    displayEmpty();
                    return;
                }

                displayHistory(results);
            })
            .catch(function(error) {
                console.error('Error loading history:', error);
                var lang = 'ar';
                if (typeof currentLang !== 'undefined') {
                    if (typeof currentLang === 'function') {
                        lang = currentLang() || 'ar';
                    } else {
                        lang = currentLang || 'ar';
                    }
                }
                displayError(error.message || (lang === 'ar' ? 'فشل في تحميل السجلات' : 'Failed to load records'));
            });
    }

    function displayEmpty() {
        if (!historyContent) return;
        var lang = 'ar';
        if (typeof currentLang !== 'undefined') {
            if (typeof currentLang === 'function') {
                lang = currentLang() || 'ar';
            } else {
                lang = currentLang || 'ar';
            }
        }
        var emptyText = typeof translate !== 'undefined' ? translate('main.history.empty') : (lang === 'ar' ? 'لا توجد تحليلات محفوظة' : 'No saved analyses');
        
        historyContent.innerHTML = '<div style="text-align: center; padding: 3rem; color: var(--text-muted);">' +
            '<i class="fa fa-history" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>' +
            '<p style="font-size: 1.1rem;">' + emptyText + '</p>' +
            '</div>';
    }

    function displayError(message) {
        if (!historyContent) return;
        historyContent.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--danger);">' +
            '<i class="fa fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>' +
            '<p>' + message + '</p>' +
            '</div>';
    }

    function displayHistory(results) {
        if (!historyContent) return;
        
        var lang = 'ar';
        if (typeof currentLang !== 'undefined') {
            if (typeof currentLang === 'function') {
                lang = currentLang() || 'ar';
            } else {
                lang = currentLang || 'ar';
            }
        }
        var t = function(key) {
            if (typeof translate !== 'undefined' && translate) {
                return translate(key);
            }
            return key;
        };
        
        var html = '<div class="history-list" style="display: grid; gap: 1rem;">';
        
        results.forEach(function(item) {
            var dateInfo = formatDate(item.created_at || item.updated_at, lang);
            var label = item.final_label || 'error';
            var score = ((item.final_score || 0) * 100).toFixed(1);
            var url = item.url || '';
            var id = item.id || '';
            
            html += '<div class="history-item" style="background: var(--surface); border-radius: var(--radius); padding: 1.5rem; border: 1px solid var(--border-color); transition: all 0.3s ease;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap;">';
            
            // معلومات الرابط والنتيجة
            html += '<div style="flex: 1; min-width: 250px;">';
            html += '<div style="margin-bottom: 0.75rem;">';
            html += '<strong style="color: var(--text-muted); font-size: 0.9rem;">' + t('main.history.url') + ':</strong> ';
            html += '<a href="' + url + '" target="_blank" style="color: var(--primary); text-decoration: none; word-break: break-all;">' + url.substring(0, 60) + (url.length > 60 ? '...' : '') + '</a>';
            html += '</div>';
            html += '<div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">';
            html += '<div><strong style="color: var(--text-muted); font-size: 0.9rem;">' + t('main.history.result') + ':</strong> ';
            html += '<span class="value ' + getLabelClass(label) + '" style="padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: bold;">' + getLabel(label) + '</span></div>';
            html += '<div><strong style="color: var(--text-muted); font-size: 0.9rem;">' + t('main.history.score') + ':</strong> ';
            html += '<span style="font-weight: bold; color: var(--primary);">' + score + '%</span></div>';
            html += '</div>';
            html += '</div>';
            
            // التواريخ
            html += '<div style="text-align: ' + (lang === 'ar' ? 'right' : 'left') + '; min-width: 200px;">';
            html += '<div style="margin-bottom: 0.5rem; font-size: 0.9rem;">';
            html += '<strong style="color: var(--text-muted);">' + t('main.history.gregorian') + ':</strong><br>';
            html += '<span style="color: var(--text);">' + (dateInfo.gregorian || dateInfo.raw.gregorian || '') + '</span>';
            html += '</div>';
            if (dateInfo.hijri) {
                html += '<div style="font-size: 0.9rem;">';
                html += '<strong style="color: var(--text-muted);">' + t('main.history.hijri') + ':</strong><br>';
                html += '<span style="color: var(--text);">' + dateInfo.hijri + '</span>';
                html += '</div>';
            }
            html += '</div>';
            
            // الأزرار
            html += '<div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">';
            html += '<a href="result.html?id=' + id + '" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.9rem; text-decoration: none;">';
            html += '<i class="fa fa-eye"></i> ' + t('main.history.view') + '</a>';
            html += '<button class="btn" style="padding: 0.5rem 1rem; font-size: 0.9rem; background: var(--surface-light);" onclick="readAnalysis(\'' + id + '\')">';
            html += '<i class="fa fa-volume-up"></i> ' + t('main.history.read') + '</button>';
            html += '<button class="btn btn-danger" style="padding: 0.5rem 1rem; font-size: 0.9rem; background: var(--danger); color: white; border: none; cursor: pointer;" onclick="deleteAnalysis(\'' + id + '\', this)">';
            html += '<i class="fa fa-trash"></i> ' + t('main.history.delete') + '</button>';
            html += '</div>';
            
            html += '</div>';
            html += '</div>';
        });
        
        html += '</div>';
        historyContent.innerHTML = html;
    }

    function readAnalysis(analysisId) {
        fetch(API + '/api/analysis/' + analysisId)
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                if (window.A11y && window.A11y.speakDetailedResults) {
                    window.A11y.speakDetailedResults(data);
                } else {
                    var lang = 'ar';
                    if (typeof currentLang !== 'undefined') {
                        if (typeof currentLang === 'function') {
                            lang = currentLang() || 'ar';
                        } else {
                            lang = currentLang || 'ar';
                        }
                    }
                    alert(lang === 'ar' ? 'ميزة القراءة الصوتية غير متاحة' : 'Audio reading feature is not available');
                }
            })
            .catch(function(error) {
                console.error('Error loading analysis:', error);
                var lang = 'ar';
                if (typeof currentLang !== 'undefined') {
                    if (typeof currentLang === 'function') {
                        lang = currentLang() || 'ar';
                    } else {
                        lang = currentLang || 'ar';
                    }
                }
                alert(lang === 'ar' ? 'فشل في تحميل التحليل' : 'Failed to load analysis');
            });
    }

    function deleteAnalysis(analysisId, buttonElement) {
        var lang = 'ar';
        if (typeof currentLang !== 'undefined') {
            if (typeof currentLang === 'function') {
                lang = currentLang() || 'ar';
            } else {
                lang = currentLang || 'ar';
            }
        }
        
        var confirmMessage = lang === 'ar' 
            ? 'هل أنت متأكد من حذف هذا التحليل؟'
            : 'Are you sure you want to delete this analysis?';
        
        if (!confirm(confirmMessage)) {
            return;
        }
        
        // تعطيل الزر وإظهار حالة التحميل
        var originalHTML = buttonElement.innerHTML;
        buttonElement.disabled = true;
        buttonElement.innerHTML = '<i class="fa fa-spinner fa-spin"></i> ' + (lang === 'ar' ? 'جاري الحذف...' : 'Deleting...');
        
        fetch(API + '/api/analysis/' + analysisId, {
            method: 'DELETE',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            if (data.message) {
                // إزالة العنصر من القائمة
                var historyItem = buttonElement.closest('.history-item');
                if (historyItem) {
                    historyItem.style.transition = 'opacity 0.3s ease';
                    historyItem.style.opacity = '0';
                    setTimeout(function() {
                        historyItem.remove();
                        // إعادة تحميل القائمة إذا لم يبق أي عنصر
                        var remainingItems = document.querySelectorAll('.history-item');
                        if (remainingItems.length === 0) {
                            loadHistory();
                        }
                    }, 300);
                } else {
                    // إعادة تحميل القائمة بالكامل
                    loadHistory();
                }
                
                // إظهار رسالة نجاح
                var successMessage = lang === 'ar' ? 'تم حذف التحليل بنجاح' : 'Analysis deleted successfully';
                var notification = document.createElement('div');
                notification.className = 'notification success';
                notification.style.cssText = 'position: fixed; top: 20px; right: 20px; background: var(--success-green); color: white; padding: 1rem 1.5rem; border-radius: var(--radius); box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000;';
                notification.innerHTML = '<i class="fa fa-check-circle"></i> ' + successMessage;
                document.body.appendChild(notification);
                setTimeout(function() {
                    notification.remove();
                }, 3000);
            } else {
                throw new Error(data.error || (lang === 'ar' ? 'فشل في حذف التحليل' : 'Failed to delete analysis'));
            }
        })
        .catch(function(error) {
            console.error('Error deleting analysis:', error);
            buttonElement.disabled = false;
            buttonElement.innerHTML = originalHTML;
            
            var errorMessage = lang === 'ar' ? 'فشل في حذف التحليل' : 'Failed to delete analysis';
            var notification = document.createElement('div');
            notification.className = 'notification error';
            notification.style.cssText = 'position: fixed; top: 20px; right: 20px; background: var(--danger); color: white; padding: 1rem 1.5rem; border-radius: var(--radius); box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000;';
            notification.innerHTML = '<i class="fa fa-exclamation-circle"></i> ' + (error.message || errorMessage);
            document.body.appendChild(notification);
            setTimeout(function() {
                notification.remove();
            }, 3000);
        });
    }

    // جعل الدالة متاحة عالمياً
    window.readAnalysis = readAnalysis;
    window.deleteAnalysis = deleteAnalysis;
    window.loadHistory = loadHistory;

    // تحميل السجلات عند تحميل الصفحة
    function initHistory() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                setTimeout(loadHistory, 500);
            });
        } else {
            setTimeout(loadHistory, 500);
        }
    }

    initHistory();
})();
