#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();
    int money{0};
    void set();
    QString str="";
    QMessageBox msgBox;
    void count(int d);

private slots:

    void on_pbcoin100_clicked();

    void on_pbcoin10_clicked();

    void on_pbcoin50_clicked();

    void on_pbcoin500_clicked();

    void on_Coffee_clicked();

    void on_Tea_clicked();

    void on_Milk_clicked();

    void on_Reset_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
