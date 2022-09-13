int func1_1(int a, int b)
{
  int c=0;
  for(int i=0; i<20; i++)
    c+=a;
  c=c*b;
  return c;
}
int func1_2(int a, int b)
{
  int c=0;
  for(int i=0; i<50; i++)
    c+=a;
  c=c/b;
  return c;
}

int func1(int a, int b)
{
  int c;
  if(a>b) c=func1_1(a, b);
  else    c=func1_2(b, a);
  return c;
}

int main()
{
  int a=3, b=5;
  int c=func1(a, b);
  if(c>10) return 1;
  return 0;
}

