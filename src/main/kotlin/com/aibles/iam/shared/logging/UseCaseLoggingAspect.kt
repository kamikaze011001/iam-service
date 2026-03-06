package com.aibles.iam.shared.logging

import com.aibles.iam.shared.error.BaseException
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.util.concurrent.ConcurrentHashMap

@Aspect
@Component
class UseCaseLoggingAspect {

    private val loggers = ConcurrentHashMap<Class<*>, org.slf4j.Logger>()

    @Around("execution(* com.aibles.iam..usecase.*.execute(..))")
    fun logUseCaseExecution(pjp: ProceedingJoinPoint): Any? {
        val targetClass = pjp.target.javaClass
        val logger = loggers.computeIfAbsent(targetClass) { LoggerFactory.getLogger(it) }
        val useCaseName = targetClass.simpleName

        logger.debug("{} starting", useCaseName)
        val start = System.currentTimeMillis()
        return try {
            val result = pjp.proceed()
            val elapsed = System.currentTimeMillis() - start
            logger.debug("{} completed in {}ms", useCaseName, elapsed)
            result
        } catch (e: Exception) {
            val elapsed = System.currentTimeMillis() - start
            if (e is BaseException) {
                logger.warn("{} failed after {}ms: [{}] {}", useCaseName, elapsed, e.errorCode, e.message)
            } else {
                logger.error("{} threw unexpected exception after {}ms", useCaseName, elapsed, e)
            }
            throw e
        }
    }
}
