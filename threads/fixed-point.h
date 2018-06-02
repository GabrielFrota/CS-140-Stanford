#ifndef THREADS_FIXED_POINT_H_
#define THREADS_FIXED_POINT_H_

#include <stdint.h>
#define F (1 << 14)

extern inline int intToFixedPoint(int n)
{
	return n*F ;
}

extern inline int fixedPointToIntZero(int x)
{
	return x/F ;
}

extern inline int fixedPointToIntNearest(int x)
{
	if (x > 0)
		return (x+F/2)/F ;
	else
		return (x-F/2)/F ;
}

extern inline int fixedPoint64ToIntNearest(int64_t x)
{
	if (x > 0)
		return ((int)(x+F/2)/F) ;
	else
		return ((int)(x-F/2)/F) ;
}

extern inline int addFixedPoint(int x, int y)
{
	return x+y ;
}

extern inline int subFixedPoint(int x, int y)
{
	return x-y ;
}

extern inline int addFixedPointInt(int x, int n)
{
	return x + n*F ;
}

extern inline int64_t addFixedPoint64Int(int64_t x, int n)
{
	return x + n*F ;
}

extern inline int subFixedPointInt(int x, int n)
{
	return x - n*F ;
}

extern inline int64_t subFixedPoint64Int(int64_t x, int n)
{
	return x - n*F ;
}

extern inline int64_t multFixedPoint(int x, int y)
{
	return ((int64_t)x) * y / F ;
}

extern inline int64_t multFixedPoint64(int64_t x, int64_t y)
{
	return x * y / F ;
}

extern inline int multFixedPointInt(int x, int n)
{
	return x*n ;
}

extern inline int64_t multFixedPoint64Int(int64_t x, int n)
{
	return x*n ;
}

extern inline int64_t divFixedPoint(int x, int y)
{
	return ((int64_t)x) * F / y ;
}

extern inline int64_t divFixedPoint64(int64_t x, int64_t y)
{
	return x * F / y ;
}

extern inline int divFixedPointInt(int x, int n)
{
	return x/n ;
}

extern inline int64_t divFixedPoint64Int(int64_t x, int n)
{
	return x/n ;
}

#endif /* THREADS_FIXED_POINT_H_ */
