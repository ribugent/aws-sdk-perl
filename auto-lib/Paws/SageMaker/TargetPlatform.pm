# Generated by default/object.tt
package Paws::SageMaker::TargetPlatform;
  use Moose;
  has Accelerator => (is => 'ro', isa => 'Str');
  has Arch => (is => 'ro', isa => 'Str', required => 1);
  has Os => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::TargetPlatform

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SageMaker::TargetPlatform object:

  $service_obj->Method(Att1 => { Accelerator => $value, ..., Os => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SageMaker::TargetPlatform object:

  $result = $service_obj->Method(...);
  $result->Att1->Accelerator

=head1 DESCRIPTION

Contains information about a target platform that you want your model
to run on, such as OS, architecture, and accelerators. It is an
alternative of C<TargetDevice>.

=head1 ATTRIBUTES


=head2 Accelerator => Str

Specifies a target platform accelerator (optional).

=over

=item *

C<NVIDIA>: Nvidia graphics processing unit. It also requires
C<gpu-code>, C<trt-ver>, C<cuda-ver> compiler options

=item *

C<MALI>: ARM Mali graphics processor

=item *

C<INTEL_GRAPHICS>: Integrated Intel graphics

=back



=head2 B<REQUIRED> Arch => Str

Specifies a target platform architecture.

=over

=item *

C<X86_64>: 64-bit version of the x86 instruction set.

=item *

C<X86>: 32-bit version of the x86 instruction set.

=item *

C<ARM64>: ARMv8 64-bit CPU.

=item *

C<ARM_EABIHF>: ARMv7 32-bit, Hard Float.

=item *

C<ARM_EABI>: ARMv7 32-bit, Soft Float. Used by Android 32-bit ARM
platform.

=back



=head2 B<REQUIRED> Os => Str

Specifies a target platform OS.

=over

=item *

C<LINUX>: Linux-based operating systems.

=item *

C<ANDROID>: Android operating systems. Android API level can be
specified using the C<ANDROID_PLATFORM> compiler option. For example,
C<"CompilerOptions": {'ANDROID_PLATFORM': 28}>

=back




=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

