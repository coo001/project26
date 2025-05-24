#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    set();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::set(){
    if(money>=100){
        ui->Coffee->setEnabled(true);
    }
    else{
        ui->Coffee->setEnabled(false);
    }
    if(money>=150){
        ui->Tea->setEnabled(true);
    }
    else{
        ui->Tea->setEnabled(false);
    }
    if(money>=200){
        ui->Milk->setEnabled(true);
    }
    else{
        ui->Milk->setEnabled(false);
    }
}

void Widget::count(int d){
    if(money/d){
        str += QString::number(d);
        str += " 원 ";
        str += QString::number(money/d);
        str += " 개 ";
        money = money%d;
        ui->lcdNumber->display(money);
    }
}

void Widget::on_pbcoin10_clicked()
{
    money += 10;
    set();
    ui->lcdNumber->display(money);
}

void Widget::on_pbcoin50_clicked()
{
    money += 50;
    set();
    ui->lcdNumber->display(money);
}

void Widget::on_pbcoin100_clicked()
{
    money += 100;
    set();
    ui->lcdNumber->display(money);
}

void Widget::on_pbcoin500_clicked()
{
    money += 500;
    set();
    ui->lcdNumber->display(money);
}


void Widget::on_Coffee_clicked()
{
    money -= 100;
    set();
    ui->lcdNumber->display(money);

}


void Widget::on_Tea_clicked()
{
    money -= 150;
    set();
    ui->lcdNumber->display(money);

}


void Widget::on_Milk_clicked()
{
    money -= 200;
    set();
    ui->lcdNumber->display(money);

}


void Widget::on_Reset_clicked()
{
    str="";
    if(money==0){
        msgBox.setText("돈이 없습니다");
        msgBox.exec();
    }
    else{
        count(500);
        count(100);
        count(50);
        count(10);
        msgBox.setText(str);
        msgBox.exec();
    }
    set();
}

