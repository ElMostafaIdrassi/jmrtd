package org.jmrtd.test.cert;

import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCAuthorizationTemplate.Permission;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;

import junit.framework.TestCase;

public class CVCAuthorizationTemplateTest extends TestCase {

  public void testCVCAuthorizationTemplate() {
    for (Role role: Role.values()) {
      for (Permission permission: Permission.values()) {
        testCVCAuthorizationTemplate(role, permission);
      }
    }
  }

  public void testCVCAuthorizationTemplate(Role role, Permission accessRight) {
    CVCAuthorizationTemplate template = new CVCAuthorizationTemplate(role, accessRight);
    assertEquals(role, template.getRole());
    assertEquals(accessRight, template.getAccessRight());
  }

//  public void testPermissionMinimal() {
//    for (Permission permission: Permission.values()) {
//      assertTrue("Failed for " + permission, Permission.READ_ACCESS_DG3_AND_DG4.implies(permission));
//    }
//  }
  
  public void testPermissionImplicationReflexive() {
    for (Permission permission: Permission.values()) {
      assertTrue(permission.implies(permission));
    }
  }
  
//  public void testPermissionImplicationTotal() {
//    for (Permission permission1: Permission.values()) {
//      for (Permission permission2: Permission.values()) {
//        assertTrue(permission1.implies(permission1) || permission2.implies(permission1));
//      }
//    }
//  }
}
